package auditor

// Stage B-1d (author decisions 2026-10-08): each node's heain-audit sends its
// signed checkpoints -- roots only, never events -- to the heain-audit of its
// zone Master, which keeps them as a witness: a node whose chain is wiped or
// rewritten after it reported a root can no longer hide it, because the
// Master holds the root it signed before. A heain-audit with a Time-Stamp
// Authority (RFC 3161) configured anchors every checkpoint it holds, its own
// and its witnessed ones, under one Merkle root the TSA stamps: only that
// SHA-256 digest leaves the deployment, and anyone can check it offline.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/heainframework/heain-sdk/heain"

	"github.com/heainframework/heain-audit/internal/merkle"
	"github.com/heainframework/heain-audit/internal/replica"
	"github.com/heainframework/heain-audit/internal/tsa"
)

// Capabilities and paths of the witness side.
const (
	CapWitness  = "audit.witness"
	PathWitness = "/v1/witness/checkpoints"
	appID       = "heain-audit"
)

// Zone is what the witness side needs from heain-sdk.
type Zone interface {
	// ZoneMaster returns this node's id and its zone Master's.
	ZoneMaster(ctx context.Context) (self, master string, err error)
	DiscoverZone(ctx context.Context, capability string, version int) ([]heain.ZoneInstance, bool, error)
	Call(ctx context.Context, cs heain.CallSpec) (int, error)
}

// Anchoring configures RFC 3161 anchoring (nil = off).
type Anchoring struct {
	URL    string        // the TSA
	CAFile string        // its CA certificate(s), to verify tokens ("" = parse only)
	Every  time.Duration // anchor what is new this often
	Client *http.Client
}

// ErrConflict: a node sent a checkpoint that contradicts one it sent before.
var ErrConflict = errors.New("auditor: the checkpoint contradicts one this node sent before")

func certDER(p []byte) []byte {
	if b, _ := pem.Decode(p); b != nil {
		return b.Bytes
	}
	return nil
}

// Witness keeps a checkpoint another node's heain-audit sent. caller is the
// sending instance and callerCert the certificate it connected with; the
// checkpoint must be signed with that very certificate, for that node.
func (a *Auditor) Witness(ctx context.Context, caller string, callerCert []byte, node string, c replica.Checkpoint) (replica.Witnessed, error) {
	if !strings.HasPrefix(caller, appID+".") {
		return replica.Witnessed{}, fmt.Errorf("only another %s may send checkpoints", appID)
	}
	if node == "" || node == a.P.Node {
		return replica.Witnessed{}, errors.New("node must name another node")
	}
	if d := certDER([]byte(c.CertPEM)); d == nil || !bytes.Equal(d, callerCert) {
		return replica.Witnessed{}, errors.New("the checkpoint is not signed with the sender's certificate")
	}
	if err := heain.VerifyDigest([]byte(c.CertPEM), digest(node, c), c.Signature); err != nil {
		return replica.Witnessed{}, fmt.Errorf("signature: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	prev, err := a.Store.WitnessedFor(node)
	if err != nil {
		return replica.Witnessed{}, err
	}
	for _, p := range prev {
		pc := p.Checkpoint
		if pc.ID == c.ID && pc.Root == c.Root && pc.LastHash == c.LastHash {
			return p, nil // sent again
		}
		if pc.From <= c.To && c.From <= pc.To { // same or overlapping range, other content
			reason := fmt.Sprintf("node %s sent checkpoint %s (root %s) over records it had already covered with %s (root %s): its chain was rewritten or wiped, or its auditor's replica was reset -- an Approver should look",
				node, c.ID, short(c.Root), pc.ID, short(pc.Root))
			_ = a.conflict(ctx, node, c, reason)
			return replica.Witnessed{}, fmt.Errorf("%w: %s", ErrConflict, reason)
		}
	}
	w := replica.Witnessed{Node: node, Checkpoint: c, From: caller, ReceivedAt: time.Now().UTC()}
	if err := a.Store.PutWitnessed(w); err != nil {
		return replica.Witnessed{}, err
	}
	_ = a.Core.Audit(ctx, CapWitness, "received", map[string]any{"node": node, "checkpoint": c.ID, "root": c.Root, "from": caller})
	return w, nil
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func (a *Auditor) conflict(ctx context.Context, node string, c replica.Checkpoint, reason string) error {
	al := replica.Alert{ID: fmt.Sprintf("wit-%s-%d", node, time.Now().UnixNano()), Seq: c.To, Reason: reason, At: time.Now().UTC()}
	res, err := a.Core.Propose(ctx, heain.Proposal{Type: TypeDivergence, Category: heain.CategoryAllowlist,
		Data: map[string]any{"node": node, "checkpoint": c.ID, "reason": reason}})
	if err == nil {
		al.ActionID = res.ActionID
	}
	_ = a.Store.PutAlert(al)
	_ = a.Core.Audit(ctx, CapWitness, "conflict", map[string]any{"node": node, "checkpoint": c.ID, "reason": reason})
	a.logf("heain-audit: WITNESS CONFLICT: %s", reason)
	return err
}

// SendPending sends this node's checkpoints the zone Master does not hold
// yet. It returns how many were sent.
func (a *Auditor) SendPending(ctx context.Context) (int, error) {
	if a.Zone == nil {
		return 0, nil
	}
	cs, err := a.Store.Checkpoints()
	if err != nil {
		return 0, err
	}
	self, master, err := a.Zone.ZoneMaster(ctx)
	if err != nil || master == "" || master == self {
		return 0, err // this node is the Master: it keeps its own
	}
	var pending []replica.Checkpoint
	for _, c := range cs {
		if a.Store.SentTo(c.ID) != master {
			pending = append(pending, c)
		}
	}
	if len(pending) == 0 {
		return 0, nil
	}
	insts, _, err := a.Zone.DiscoverZone(ctx, CapWitness, 1)
	if err != nil {
		return 0, err
	}
	var to *heain.ZoneInstance
	for i := range insts {
		if insts[i].Node == master && insts[i].AppID == appID && insts[i].EndpointBase != "" {
			to = &insts[i]
			break
		}
	}
	if to == nil {
		return 0, fmt.Errorf("no %s on the zone Master %s yet", appID, master)
	}
	n := 0
	for _, c := range pending {
		if _, err := a.Zone.Call(ctx, heain.CallSpec{App: appID, Capability: CapWitness, Version: 1, Instance: to.InstanceID,
			Scope: heain.ScopeZone, Method: http.MethodPost, Path: PathWitness,
			Body: map[string]any{"node": a.P.Node, "checkpoint": c}, Timeout: 15 * time.Second}); err != nil {
			return n, fmt.Errorf("sending %s to %s: %w", c.ID, master, err)
		}
		if err := a.Store.MarkSent(c.ID, master); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// leaf is a checkpoint digest an anchor covers.
func leaf(node string, c replica.Checkpoint) replica.Leaf {
	return replica.Leaf{Node: node, Checkpoint: c.ID, Digest: hex.EncodeToString(digest(node, c))}
}

// ErrNoAnchoring: no TSA configured.
var ErrNoAnchoring = errors.New("auditor: no time-stamp authority configured (-tsa-url)")

// Anchor stamps, under one Merkle root, every checkpoint held here (its own
// and the witnessed ones) that no anchor covers yet.
func (a *Auditor) Anchor(ctx context.Context) (replica.Anchor, error) {
	if a.Anchoring == nil || a.Anchoring.URL == "" {
		return replica.Anchor{}, ErrNoAnchoring
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.anchor(ctx)
}

func (a *Auditor) anchor(ctx context.Context) (replica.Anchor, error) {
	prev, err := a.Store.Anchors()
	if err != nil {
		return replica.Anchor{}, err
	}
	done := map[string]bool{}
	for _, an := range prev {
		for _, l := range an.Leaves {
			done[l.Node+"/"+l.Checkpoint] = true
		}
	}
	var leaves []replica.Leaf
	own, _ := a.Store.Checkpoints()
	for _, c := range own {
		if !done[a.P.Node+"/"+c.ID] {
			leaves = append(leaves, leaf(a.P.Node, c))
		}
	}
	wit, _ := a.Store.WitnessedFor("")
	for _, w := range wit {
		if !done[w.Node+"/"+w.Checkpoint.ID] {
			leaves = append(leaves, leaf(w.Node, w.Checkpoint))
		}
	}
	if len(leaves) == 0 {
		return replica.Anchor{}, ErrNothingNew
	}
	hs := make([]string, len(leaves))
	for i, l := range leaves {
		hs[i] = l.Digest
	}
	root, err := merkle.Root(hs)
	if err != nil {
		return replica.Anchor{}, err
	}
	rb, _ := hex.DecodeString(root)
	tok, err := tsa.Stamp(ctx, a.Anchoring.URL, rb, a.Anchoring.Client)
	if err != nil {
		return replica.Anchor{}, err
	}
	an := replica.Anchor{ID: fmt.Sprintf("an-%06d", len(prev)+1), Root: root, Leaves: leaves, TSA: a.Anchoring.URL,
		Token: tok.DER, GenTime: tok.GenTime, Serial: tok.Serial, Recorded: time.Now().UTC()}
	if err := a.Store.PutAnchor(an); err != nil {
		return replica.Anchor{}, err
	}
	_ = a.Core.Audit(ctx, "audit.anchor", "stamped", map[string]any{"anchor": an.ID, "root": root, "leaves": len(leaves),
		"tsa": a.Anchoring.URL, "gen_time": tok.GenTime, "serial": tok.Serial})
	a.logf("heain-audit: anchor %s: %d checkpoint(s) under root %s, stamped %s by %s", an.ID, len(leaves), short(root), tok.GenTime.Format(time.RFC3339), a.Anchoring.URL)
	return an, nil
}

// AnchorCheck is GET /v1/anchors/{id}/verify.
type AnchorCheck struct {
	ID          string    `json:"id"`
	RootOK      bool      `json:"root_ok"`    // the leaves still give the root
	TokenOK     bool      `json:"token_ok"`   // the token stamps that root
	TSASigOK    *bool     `json:"tsa_sig_ok"` // the TSA's signature (nil: no CA configured)
	LeavesOK    bool      `json:"leaves_ok"`  // every leaf is a checkpoint held here, its signature valid
	GenTime     time.Time `json:"gen_time"`
	Detail      string    `json:"detail,omitempty"`
	OfflineHint string    `json:"offline_check"`
}

// VerifyAnchor re-checks an anchor: leaves, root, token and TSA signature.
func (a *Auditor) VerifyAnchor(ctx context.Context, id string) (AnchorCheck, error) {
	an, err := a.Store.Anchor(id)
	if err != nil {
		return AnchorCheck{}, err
	}
	v := AnchorCheck{ID: id, GenTime: an.GenTime,
		OfflineHint: "GET /v1/anchors/" + id + "/token > " + id + ".tsr; openssl ts -verify -digest " + an.Root + " -token_in -in " + id + ".tsr -CAfile <tsa-ca.pem>"}
	hs := make([]string, len(an.Leaves))
	for i, l := range an.Leaves {
		hs[i] = l.Digest
	}
	if r, err := merkle.Root(hs); err == nil {
		v.RootOK = r == an.Root
	}
	rb, _ := hex.DecodeString(an.Root)
	if info, err := tsa.Parse(an.Token); err == nil {
		v.TokenOK = bytes.Equal(info.MessageImprint.HashedMessage, rb)
	}
	if a.Anchoring != nil && a.Anchoring.CAFile != "" {
		ok := tsa.Verify(an.Token, rb, a.Anchoring.CAFile) == nil
		v.TSASigOK = &ok
	}
	v.LeavesOK = true
	for _, l := range an.Leaves {
		var c replica.Checkpoint
		var found bool
		if l.Node == a.P.Node {
			if cp, err := a.Store.Checkpoint(l.Checkpoint); err == nil {
				c, found = cp, true
			}
		} else if ws, err := a.Store.WitnessedFor(l.Node); err == nil {
			for _, w := range ws {
				if w.Checkpoint.ID == l.Checkpoint {
					c, found = w.Checkpoint, true
				}
			}
		}
		if !found || hex.EncodeToString(digest(l.Node, c)) != l.Digest || heain.VerifyDigest([]byte(c.CertPEM), digest(l.Node, c), c.Signature) != nil {
			v.LeavesOK = false
			v.Detail = "leaf " + l.Node + "/" + l.Checkpoint + " does not match a signed checkpoint held here"
			break
		}
	}
	return v, nil
}

// zoneWork sends pending checkpoints and anchors what is due; called after
// every pull.
func (a *Auditor) zoneWork(ctx context.Context) {
	if n, err := a.SendPending(ctx); err != nil {
		a.logf("heain-audit: sending checkpoints to the zone Master: %v", err)
	} else if n > 0 {
		a.logf("heain-audit: %d checkpoint(s) sent to the zone Master", n)
	}
	if a.Anchoring == nil || a.Anchoring.URL == "" || a.Anchoring.Every <= 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if as, _ := a.Store.Anchors(); len(as) > 0 && time.Since(as[len(as)-1].Recorded) < a.Anchoring.Every {
		return
	}
	if _, err := a.anchor(ctx); err != nil && !errors.Is(err, ErrNothingNew) {
		a.logf("heain-audit: anchoring: %v", err)
	}
}

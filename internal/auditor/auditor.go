// Package auditor is heain-audit's work: pull the node's audit chain from
// heain-core, verify every link itself, keep an independent replica, detect
// a rewritten or truncated chain (divergence), sign Merkle checkpoints, and
// score events for anomalies with an Isolation Forest (advisory: findings
// go to an Approver through P5, never acted on by heain-audit itself).
package auditor

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/heainframework/heain-sdk/core"
	"github.com/heainframework/heain-sdk/heain"

	"github.com/heainframework/heain-audit/internal/iforest"
	"github.com/heainframework/heain-audit/internal/merkle"
	"github.com/heainframework/heain-audit/internal/replica"
)

// Core is what the auditor needs from heain-sdk (*heain.App).
type Core interface {
	AuditRecords(ctx context.Context, from uint64, limit int) (heain.AuditPage, error)
	SignDigest(digest []byte) ([]byte, error)
	CertificatePEM() []byte
	Reason(ctx context.Context, d heain.Decision) (string, error)
	Propose(ctx context.Context, p heain.Proposal) (heain.PolicyResult, error)
	Audit(ctx context.Context, capability, outcome string, detail map[string]any) error
}

// Params tune the auditor.
type Params struct {
	Node            string  // the core node id (bound into checkpoints)
	CheckpointEvery uint64  // sign a checkpoint every this many new records (0 = only on request)
	ScanEvery       uint64  // score after this many new records (0 = only on request)
	Threshold       float64 // anomaly score at or above which an event is flagged
	Trees, Sample   int
	Context         int // earlier events fitted with the window, for context
}

// Status is GET /v1/status.
type Status struct {
	ReaderAllowed  bool      `json:"reader_allowed"`
	CoreHead       uint64    `json:"core_head"`
	ReplicaHead    uint64    `json:"replica_head"`
	ScoredThrough  uint64    `json:"scored_through"`
	Diverged       bool      `json:"diverged"`
	Alerts         int       `json:"alerts"`
	Checkpoints    int       `json:"checkpoints"`
	LastCheckpoint uint64    `json:"last_checkpoint_to"`
	Flags          int       `json:"flags"`
	LastPull       time.Time `json:"last_pull_at"`
	LastError      string    `json:"last_error,omitempty"`
}

// Auditor runs the work against one core.
type Auditor struct {
	Core  Core
	Store *replica.Store
	P     Params
	Logf  func(string, ...any)
	// Zone and Anchoring (Stage B-1d, witness.go): nil = off.
	Zone      Zone
	Anchoring *Anchoring

	mu       sync.Mutex // one pull/scan/checkpoint at a time
	st       Status
	pulls    int
	coreSeen string // the hash core showed for the replica head at the last pull
}

const (
	TypeDivergence    = "audit.divergence"
	TypeAnomalyReview = "audit.anomaly_review"
	ModelName         = "isolation-forest"
)

// ErrNothingNew: no record since the last checkpoint.
var ErrNothingNew = errors.New("auditor: no new records since the last checkpoint")

func (a *Auditor) logf(f string, v ...any) {
	if a.Logf != nil {
		a.Logf(f, v...)
	}
}

// Status reports the current state.
func (a *Auditor) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.st
	s.ReplicaHead, _ = a.Store.Head()
	s.ScoredThrough = a.Store.Meta("scored")
	al, _ := a.Store.Alerts()
	cs, _ := a.Store.Checkpoints()
	fl, _ := a.Store.Flags()
	s.Alerts, s.Checkpoints, s.Flags = len(al), len(cs), len(fl)
	s.Diverged = len(al) > 0
	if len(cs) > 0 {
		s.LastCheckpoint = cs[len(cs)-1].To
	}
	return s
}

// Run pulls every interval until ctx ends.
func (a *Auditor) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := a.Pull(ctx); err != nil && ctx.Err() == nil {
			a.logf("heain-audit: pull: %v", err)
		}
		if ctx.Err() == nil {
			a.zoneWork(ctx)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func notReader(err error) bool {
	var ce *core.Error
	return errors.As(err, &ce) && ce.Code == "audit_reader_not_allowed"
}

// Pull reads what core has beyond the replica, verifies and keeps it.
func (a *Auditor) Pull(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	err := a.pull(ctx)
	a.st.LastPull = time.Now().UTC()
	a.st.LastError = ""
	if err != nil {
		a.st.LastError = err.Error()
	}
	return err
}

func (a *Auditor) pull(ctx context.Context) error {
	if al, _ := a.Store.Alerts(); len(al) > 0 {
		return nil // frozen after a divergence: the replica stays the evidence
	}
	for {
		seq, hash := a.Store.Head()
		from := seq
		if from == 0 {
			from = 1
		}
		page, err := a.Core.AuditRecords(ctx, from, 500)
		if err != nil {
			if notReader(err) {
				a.st.ReaderAllowed = false
				return nil
			}
			return err
		}
		a.st.ReaderAllowed, a.st.CoreHead = true, page.Head.Seq
		recs := page.Records
		if seq > 0 {
			// the record the replica ends with must still be in core, unchanged
			if page.Head.Seq < seq || len(recs) == 0 || recs[0].Seq != seq {
				return a.diverge(ctx, seq, fmt.Sprintf("core's chain ends at %d, before the replica's %d (truncated or replaced)", page.Head.Seq, seq))
			}
			if recs[0].Hash != hash {
				return a.diverge(ctx, seq, "core's record differs from the replica's (history rewritten)")
			}
			recs = recs[1:]
		}
		if len(recs) == 0 {
			break
		}
		if _, err := heain.VerifyAuditRecords(hash, recs); err != nil {
			return a.diverge(ctx, recs[0].Seq, err.Error())
		}
		if err := a.Store.Append(recs); err != nil {
			return err
		}
		if len(page.Records) < 500 {
			break
		}
	}
	a.pulls++
	if a.pulls%10 == 0 {
		if err := a.checkLastCheckpoint(ctx); err != nil {
			return err
		}
	}
	head, _ := a.Store.Head()
	cs, _ := a.Store.Checkpoints()
	var lastCp uint64
	if len(cs) > 0 {
		lastCp = cs[len(cs)-1].To
	}
	if a.P.CheckpointEvery > 0 && head-lastCp >= a.P.CheckpointEvery {
		if _, err := a.checkpoint(ctx); err != nil && !errors.Is(err, ErrNothingNew) {
			return err
		}
	}
	if a.P.ScanEvery > 0 && head-a.Store.Meta("scored") >= a.P.ScanEvery {
		if _, err := a.scan(ctx); err != nil {
			return err
		}
	}
	return nil
}

// checkLastCheckpoint re-reads the last checkpointed record from core: a
// chain recomputed after it would show a different hash there.
func (a *Auditor) checkLastCheckpoint(ctx context.Context) error {
	cs, _ := a.Store.Checkpoints()
	if len(cs) == 0 {
		return nil
	}
	cp := cs[len(cs)-1]
	page, err := a.Core.AuditRecords(ctx, cp.To, 1)
	if err != nil {
		return err
	}
	if len(page.Records) == 0 || page.Records[0].Seq != cp.To || page.Records[0].Hash != cp.LastHash {
		return a.diverge(ctx, cp.To, "core no longer reproduces checkpoint "+cp.ID)
	}
	return nil
}

func (a *Auditor) diverge(ctx context.Context, seq uint64, reason string) error {
	al := replica.Alert{ID: fmt.Sprintf("div-%d-%d", seq, time.Now().UnixNano()), Seq: seq, Reason: reason, At: time.Now().UTC()}
	res, err := a.Core.Propose(ctx, heain.Proposal{Type: TypeDivergence, Category: heain.CategoryAllowlist,
		Data: map[string]any{"node": a.P.Node, "seq": seq, "reason": reason}})
	if err == nil {
		al.ActionID = res.ActionID
	}
	_ = a.Store.PutAlert(al)
	_ = a.Core.Audit(ctx, "audit.verify", "error:divergence", map[string]any{"seq": seq, "reason": reason, "action_id": al.ActionID})
	a.logf("heain-audit: DIVERGENCE at %d: %s (P5 %s)", seq, reason, al.ActionID)
	return fmt.Errorf("divergence at %d: %s", seq, reason)
}

// ---- checkpoints

func digest(node string, c replica.Checkpoint) []byte {
	h := sha256.Sum256([]byte(fmt.Sprintf("heain-audit checkpoint v1|%s|%d|%d|%s|%s", node, c.From, c.To, c.Root, c.LastHash)))
	return h[:]
}

// Checkpoint signs a Merkle root over the records since the last one.
func (a *Auditor) Checkpoint(ctx context.Context) (replica.Checkpoint, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.checkpoint(ctx)
}

func (a *Auditor) checkpoint(ctx context.Context) (replica.Checkpoint, error) {
	cs, _ := a.Store.Checkpoints()
	from := uint64(1)
	if len(cs) > 0 {
		from = cs[len(cs)-1].To + 1
	}
	to, last := a.Store.Head()
	if to < from {
		return replica.Checkpoint{}, ErrNothingNew
	}
	hs, err := a.Store.Hashes(from, to)
	if err != nil {
		return replica.Checkpoint{}, err
	}
	root, err := merkle.Root(hs)
	if err != nil {
		return replica.Checkpoint{}, err
	}
	c := replica.Checkpoint{ID: fmt.Sprintf("cp-%08d-%08d", from, to), From: from, To: to, Root: root, LastHash: last,
		CertPEM: string(a.Core.CertificatePEM()), CreatedAt: time.Now().UTC()}
	if c.Signature, err = a.Core.SignDigest(digest(a.P.Node, c)); err != nil {
		return replica.Checkpoint{}, err
	}
	if err := a.Store.PutCheckpoint(c); err != nil {
		return replica.Checkpoint{}, err
	}
	_ = a.Core.Audit(ctx, "audit.checkpoint", "created", map[string]any{"checkpoint": c.ID, "from": from, "to": to, "root": root})
	return c, nil
}

// Verification is GET /v1/checkpoints/{id}/verify.
type Verification struct {
	ID          string `json:"id"`
	RootOK      bool   `json:"root_ok"`      // the replica still gives the signed root
	SignatureOK bool   `json:"signature_ok"` // the signature verifies with the stored certificate
	CoreOK      bool   `json:"core_ok"`      // core's chain still has the checkpoint's last hash
	Detail      string `json:"detail,omitempty"`
}

// Verify re-checks a checkpoint against the replica, its signature and core.
func (a *Auditor) Verify(ctx context.Context, id string) (Verification, error) {
	c, err := a.Store.Checkpoint(id)
	if err != nil {
		return Verification{}, err
	}
	v := Verification{ID: id}
	if hs, err := a.Store.Hashes(c.From, c.To); err == nil {
		r, _ := merkle.Root(hs)
		v.RootOK = r == c.Root
	}
	v.SignatureOK = heain.VerifyDigest([]byte(c.CertPEM), digest(a.P.Node, c), c.Signature) == nil
	page, err := a.Core.AuditRecords(ctx, c.To, 1)
	switch {
	case err != nil:
		v.Detail = "core: " + err.Error()
	case len(page.Records) == 0 || page.Records[0].Seq != c.To:
		v.Detail = "core no longer has the checkpoint's last record"
	default:
		v.CoreOK = page.Records[0].Hash == c.LastHash
	}
	return v, nil
}

// ---- anomaly scoring

// Scan is the result of one anomaly scan.
type Scan struct {
	From, To  uint64         `json:"-"`
	Window    [2]uint64      `json:"window"`
	Scored    int            `json:"scored"`
	Flagged   []replica.Flag `json:"flagged"`
	MaxScore  float64        `json:"max_score"`
	RecordID  string         `json:"record_id"`
	ActionID  string         `json:"action_id,omitempty"`
	Threshold float64        `json:"threshold"`
}

// ScanNow scores the records not scored yet (ctx carries the request's
// trace, so the reasoning record is attached to the call).
func (a *Auditor) ScanNow(ctx context.Context) (Scan, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.scan(ctx)
}

var featureNames = []string{"gap_log_s", "action_freq", "actor_freq", "hour", "failure"}

func failure(result string) bool {
	r := strings.ToLower(result)
	return strings.HasPrefix(r, "error") || strings.HasPrefix(r, "refused") || strings.Contains(r, "denied") ||
		strings.Contains(r, "violation") || strings.Contains(r, "rejected")
}

func features(es []replica.Entry) [][]float64 {
	act, who := map[string]int{}, map[string]int{}
	for _, e := range es {
		act[e.Event.Action]++
		who[e.Event.Actor]++
	}
	n := float64(len(es))
	out := make([][]float64, len(es))
	for i, e := range es {
		gap := 0.0
		if i > 0 {
			gap = math.Log1p(math.Max(0, e.Event.Timestamp.Sub(es[i-1].Event.Timestamp).Seconds()))
		}
		f := 0.0
		if failure(e.Event.Result) {
			f = 1
		}
		out[i] = []float64{gap, float64(act[e.Event.Action]) / n, float64(who[e.Event.Actor]) / n, float64(e.Event.Timestamp.Hour()) / 23, f}
	}
	return out
}

func (a *Auditor) modelHash() string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s/1 trees=%d sample=%d threshold=%g context=%d features=%s",
		ModelName, a.P.Trees, a.P.Sample, a.P.Threshold, a.P.Context, strings.Join(featureNames, ","))))
	return hex.EncodeToString(h[:])
}

func (a *Auditor) scan(ctx context.Context) (Scan, error) {
	head, _ := a.Store.Head()
	scored := a.Store.Meta("scored")
	sc := Scan{From: scored + 1, To: head, Threshold: a.P.Threshold}
	sc.Window = [2]uint64{sc.From, sc.To}
	var es []replica.Entry
	ctxFrom := uint64(1)
	if sc.From > uint64(a.P.Context) {
		ctxFrom = sc.From - uint64(a.P.Context)
	}
	if head >= sc.From {
		var err error
		if es, err = a.Store.Events(ctxFrom, int(head-ctxFrom+1), "", ""); err != nil {
			return sc, err
		}
	}
	var seed int64
	if len(es) > 0 {
		h := sha256.Sum256([]byte(es[0].Hash + es[len(es)-1].Hash))
		seed = int64(binary.BigEndian.Uint64(h[:8]) >> 1)
	}
	x := features(es)
	if len(es) >= 8 {
		f := iforest.Fit(x, iforest.Params{Trees: a.P.Trees, Sample: a.P.Sample, Seed: seed})
		for i, e := range es {
			if e.Seq < sc.From {
				continue
			}
			sc.Scored++
			s := f.Score(x[i])
			sc.MaxScore = math.Max(sc.MaxScore, s)
			if s >= a.P.Threshold {
				fs := map[string]float64{}
				for j, n := range featureNames {
					fs[n] = math.Round(x[i][j]*1000) / 1000
				}
				sc.Flagged = append(sc.Flagged, replica.Flag{Seq: e.Seq, Score: math.Round(s*1000) / 1000, Action: e.Event.Action, Actor: e.Event.Actor, Features: fs, At: time.Now().UTC()})
			}
		}
	}
	sort.Slice(sc.Flagged, func(i, j int) bool { return sc.Flagged[i].Score > sc.Flagged[j].Score })
	decision := fmt.Sprintf("flagged %d of %d events in %d-%d", len(sc.Flagged), sc.Scored, sc.From, sc.To)
	summary := "Isolation Forest over gap, action/actor rarity, hour and failure; events at or above the threshold are flagged for an Approver (advisory)."
	if len(es) < 8 {
		decision, summary = "not scored: fewer than 8 events", "too few events to fit a model"
	}
	conf := 1 - math.Min(1, sc.MaxScore)
	in := []byte(fmt.Sprintf("%d-%d", sc.From, sc.To))
	for _, e := range es {
		in = append(in, e.Hash...)
	}
	rid, err := a.Core.Reason(ctx, heain.Decision{Capability: "audit.anomaly", Input: in, InputDataClass: "audit_replica",
		InputRef: fmt.Sprintf("audit-chain/%s/%d-%d", a.P.Node, sc.From, sc.To), Decision: decision,
		Value:     map[string]any{"flagged": len(sc.Flagged), "scored": sc.Scored, "max_score": math.Round(sc.MaxScore*1000) / 1000},
		Threshold: &heain.Threshold{Name: "anomaly_score", Value: a.P.Threshold, Source: "app"}, Confidence: &conf, Summary: summary,
		Factors: []heain.Factor{{Name: "events_scored", Value: sc.Scored}, {Name: "context_events", Value: len(es) - sc.Scored},
			{Name: "flagged", Value: len(sc.Flagged)}, {Name: "trees", Value: a.P.Trees}, {Name: "seed", Value: seed}},
		Role: "advisory", ModelSHA256: a.modelHash(), Runtime: "heain-audit iforest (go)"})
	if err != nil {
		return sc, fmt.Errorf("reasoning record: %w", err)
	}
	sc.RecordID = rid
	if len(sc.Flagged) > 0 {
		seqs := []uint64{}
		for i, f := range sc.Flagged {
			if i < 20 {
				seqs = append(seqs, f.Seq)
			}
		}
		res, err := a.Core.Propose(ctx, heain.Proposal{Type: TypeAnomalyReview, Category: heain.CategoryThreshold, Value: sc.MaxScore,
			Data: map[string]any{"node": a.P.Node, "from": sc.From, "to": sc.To, "flagged": len(sc.Flagged), "seqs": seqs, "record_id": rid}})
		if err == nil {
			sc.ActionID = res.ActionID
		}
		for _, f := range sc.Flagged {
			f.RecordID, f.ActionID = rid, sc.ActionID
			_ = a.Store.PutFlag(f)
		}
	}
	if sc.To >= sc.From {
		_ = a.Store.SetMeta("scored", sc.To)
	}
	return sc, nil
}

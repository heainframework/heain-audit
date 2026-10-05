package auditor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/heainframework/heain-sdk/core"
	"github.com/heainframework/heain-sdk/heain"

	"github.com/heainframework/heain-audit/internal/replica"
)

type fakeCore struct {
	recs      []heain.AuditRecord
	reader    bool
	key       *ecdsa.PrivateKey
	cert      []byte
	reasons   []heain.Decision
	proposals []heain.Proposal
	audits    []string
}

func newFake(t *testing.T) *fakeCore {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "heain-audit.a1"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	return &fakeCore{reader: true, key: k, cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (f *fakeCore) add(actor, action, result string, at time.Time) {
	prev := make([]byte, 32)
	if n := len(f.recs); n > 0 {
		prev, _ = hex.DecodeString(f.recs[n-1].Hash)
	}
	seq := uint64(len(f.recs) + 1)
	ct := []byte(action + actor)
	h := heain.AuditChainHash(prev, seq, ct)
	f.recs = append(f.recs, heain.AuditRecord{Seq: seq, PrevHash: hex.EncodeToString(prev), Hash: hex.EncodeToString(h), Ciphertext: ct,
		Event: heain.AuditEvent{Timestamp: at, Actor: actor, Action: action, Result: result}})
}

func (f *fakeCore) AuditRecords(_ context.Context, from uint64, limit int) (heain.AuditPage, error) {
	var p heain.AuditPage
	if !f.reader {
		return p, &core.Error{Status: 403, Code: "audit_reader_not_allowed"}
	}
	for _, r := range f.recs {
		if r.Seq >= from && len(p.Records) < limit {
			p.Records = append(p.Records, r)
		}
	}
	if n := len(f.recs); n > 0 {
		p.Head.Seq, p.Head.Hash = f.recs[n-1].Seq, f.recs[n-1].Hash
	}
	return p, nil
}
func (f *fakeCore) SignDigest(d []byte) ([]byte, error) { return ecdsa.SignASN1(rand.Reader, f.key, d) }
func (f *fakeCore) CertificatePEM() []byte              { return f.cert }
func (f *fakeCore) Reason(_ context.Context, d heain.Decision) (string, error) {
	f.reasons = append(f.reasons, d)
	return "rec-" + string(rune('a'+len(f.reasons))), nil
}
func (f *fakeCore) Propose(_ context.Context, p heain.Proposal) (heain.PolicyResult, error) {
	f.proposals = append(f.proposals, p)
	return heain.PolicyResult{ActionID: "appp5-x", Result: heain.ResultWaitingApproval}, nil
}
func (f *fakeCore) Audit(_ context.Context, c, o string, _ map[string]any) error {
	f.audits = append(f.audits, c+"/"+o)
	return nil
}

func setup(t *testing.T) (*Auditor, *fakeCore) {
	s, _ := heain.NewSealer(bytes.Repeat([]byte{9}, 32))
	st, err := replica.Open(filepath.Join(t.TempDir(), "r.db"), s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	f := newFake(t)
	return &Auditor{Core: f, Store: st, P: Params{Node: "G", Threshold: 0.62, Trees: 100, Sample: 256, Context: 200}}, f
}

func TestPullCheckpointVerify(t *testing.T) {
	a, f := setup(t)
	ctx := context.Background()
	f.reader = false
	if err := a.Pull(ctx); err != nil || a.Status().ReaderAllowed {
		t.Fatal("not a reader yet: no error, reader_allowed false")
	}
	f.reader = true
	base := time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 1200; i++ {
		f.add("app.a1", "app.event", "ok", base.Add(time.Duration(i)*time.Second))
	}
	if err := a.Pull(ctx); err != nil {
		t.Fatal(err)
	}
	if st := a.Status(); st.ReplicaHead != 1200 || st.CoreHead != 1200 || !st.ReaderAllowed {
		t.Fatalf("%+v", st)
	}
	c, err := a.Checkpoint(ctx)
	if err != nil || c.From != 1 || c.To != 1200 {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := a.Checkpoint(ctx); err != ErrNothingNew {
		t.Fatal("nothing new")
	}
	v, _ := a.Verify(ctx, c.ID)
	if !v.RootOK || !v.SignatureOK || !v.CoreOK {
		t.Fatalf("%+v", v)
	}
	// core's chain is replaced from scratch (operator wiped it): divergence
	f.recs = nil
	for i := 0; i < 5; i++ {
		f.add("app.a1", "app.event", "ok", base)
	}
	if err := a.Pull(ctx); err == nil || !strings.Contains(err.Error(), "divergence") {
		t.Fatalf("divergence expected: %v", err)
	}
	st := a.Status()
	if !st.Diverged || st.Alerts != 1 || len(f.proposals) != 1 || f.proposals[0].Type != TypeDivergence {
		t.Fatalf("alert + P5: %+v %+v", st, f.proposals)
	}
	if v, _ := a.Verify(ctx, c.ID); v.CoreOK || !v.RootOK || !v.SignatureOK {
		t.Fatalf("the checkpoint still verifies on the replica, not on core: %+v", v)
	}
	if err := a.Pull(ctx); err != nil || a.Status().ReplicaHead != 1200 {
		t.Fatal("frozen after a divergence: the replica stays the evidence")
	}
}

func TestRewriteDetected(t *testing.T) {
	a, f := setup(t)
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		f.add("app.a1", "x", "ok", time.Now())
	}
	_ = a.Pull(ctx)
	// rewrite record 10 and recompute everything after it consistently
	old := f.recs
	f.recs = old[:9]
	for i := 9; i < 20; i++ {
		f.add("app.a1", "x-rewritten", "ok", time.Now())
	}
	f.add("app.a1", "x", "ok", time.Now())
	if err := a.Pull(ctx); err == nil {
		t.Fatal("a consistently recomputed chain must not pass")
	}
}

func TestScanFlagsOutliers(t *testing.T) {
	a, f := setup(t)
	ctx := context.Background()
	base := time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 300; i++ {
		f.add([]string{"app.a1", "app.a2", "app.a3"}[i%3], []string{"app.event", "app.job_submitted"}[i%2], "ok", base.Add(time.Duration(i*2)*time.Second))
	}
	for i := 0; i < 3; i++ {
		f.add("intruder.z9", "app.key_destroyed", "error:denied", base.Add(time.Duration(600+i*3600)*time.Second))
	}
	_ = a.Pull(ctx)
	sc, err := a.ScanNow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Scored != 303 || len(sc.Flagged) == 0 || sc.RecordID == "" {
		t.Fatalf("%+v", sc)
	}
	intr := 0
	for _, fl := range sc.Flagged {
		if fl.Actor == "intruder.z9" {
			intr++
		}
	}
	if intr != 3 || len(sc.Flagged) > 10 {
		t.Fatalf("the 3 intruder events must be flagged, few others: %d of %d", intr, len(sc.Flagged))
	}
	if len(f.proposals) != 1 || f.proposals[0].Type != TypeAnomalyReview || f.proposals[0].Value < 0.62 {
		t.Fatalf("one P5 review: %+v", f.proposals)
	}
	if len(f.reasons) != 1 || f.reasons[0].Capability != "audit.anomaly" || f.reasons[0].ModelSHA256 == "" {
		t.Fatal("a reasoning record per scan")
	}
	if fl, _ := a.Store.Flags(); len(fl) != len(sc.Flagged) || fl[0].RecordID == "" {
		t.Fatal("flags stored with their record")
	}
	sc2, _ := a.ScanNow(ctx)
	if sc2.Scored != 0 || len(f.reasons) != 2 {
		t.Fatal("nothing new: still a record, nothing scored")
	}
	_ = sha256.New
}

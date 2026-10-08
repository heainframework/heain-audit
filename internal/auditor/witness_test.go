package auditor

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/heainframework/heain-audit/internal/tsa"
)

// workerCheckpoint makes a checkpoint on a "worker" auditor over n records.
func workerCheckpoint(t *testing.T, n int) (*Auditor, *fakeCore) {
	w, wf := setup(t)
	w.P.Node = "W"
	for i := 0; i < n; i++ {
		wf.add("app.x", "act", "ok", time.Now())
	}
	if err := w.Pull(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Checkpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	return w, wf
}

func der(p []byte) []byte { b, _ := pem.Decode(p); return b.Bytes }

func TestWitnessAndConflict(t *testing.T) {
	ctx := context.Background()
	m, mf := setup(t) // the Master's heain-audit
	w, wf := workerCheckpoint(t, 5)
	cs, _ := w.Store.Checkpoints()
	c := cs[0]
	if _, err := m.Witness(ctx, "heain-audit.w1", der(wf.cert), "W", c); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Witness(ctx, "heain-audit.w1", der(wf.cert), "W", c); err != nil {
		t.Fatal("sending the same checkpoint again is fine")
	}
	if _, err := m.Witness(ctx, "other.o1", der(wf.cert), "W", c); err == nil {
		t.Fatal("only heain-audit may send")
	}
	if _, err := m.Witness(ctx, "heain-audit.x1", der(mf.cert), "W", c); err == nil {
		t.Fatal("a checkpoint signed with another certificate than the sender's must be refused")
	}
	if _, err := m.Witness(ctx, "heain-audit.w1", der(wf.cert), "Z", c); err == nil {
		t.Fatal("a checkpoint presented for another node must fail its signature")
	}
	// W's chain is wiped and refilled: its new first checkpoint covers the same records with another root
	w2, wf2 := setup(t)
	w2.P.Node = "W"
	wf2.key, wf2.cert = wf.key, wf.cert
	for i := 0; i < 7; i++ {
		wf2.add("app.y", "other", "ok", time.Now())
	}
	_ = w2.Pull(ctx)
	c2, _ := w2.Checkpoint(ctx)
	if _, err := m.Witness(ctx, "heain-audit.w1", der(wf.cert), "W", c2); !errors.Is(err, ErrConflict) {
		t.Fatalf("a rewritten chain must be a conflict: %v", err)
	}
	if al, _ := m.Store.Alerts(); len(al) != 1 || len(mf.proposals) != 1 || mf.proposals[0].Type != TypeDivergence {
		t.Fatal("a conflict raises an alert and P5 audit.divergence")
	}
}

func TestAnchor(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	ctx := context.Background()
	ta := tsa.TestAuthority{Dir: t.TempDir()}
	if err := ta.Setup(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(ta)
	defer srv.Close()
	m, mf := setup(t)
	for i := 0; i < 4; i++ {
		mf.add("core", "act", "ok", time.Now())
	}
	_ = m.Pull(ctx)
	_, _ = m.Checkpoint(ctx)
	w, wf := workerCheckpoint(t, 3)
	wc, _ := w.Store.Checkpoints()
	_, _ = m.Witness(ctx, "heain-audit.w1", der(wf.cert), "W", wc[0])
	if _, err := m.Anchor(ctx); !errors.Is(err, ErrNoAnchoring) {
		t.Fatal("no TSA, no anchor")
	}
	m.Anchoring = &Anchoring{URL: srv.URL, CAFile: filepath.Join(ta.Dir, "ca.pem")}
	an, err := m.Anchor(ctx)
	if err != nil || len(an.Leaves) != 2 {
		t.Fatalf("anchor: %v %d", err, len(an.Leaves))
	}
	if _, err := m.Anchor(ctx); !errors.Is(err, ErrNothingNew) {
		t.Fatal("nothing new to anchor")
	}
	v, err := m.VerifyAnchor(ctx, an.ID)
	if err != nil || !v.RootOK || !v.TokenOK || v.TSASigOK == nil || !*v.TSASigOK || !v.LeavesOK {
		t.Fatalf("verify: %+v %v", v, err)
	}
	// a tampered leaf no longer gives the root
	an.Leaves[0].Digest = an.Leaves[1].Digest
	_ = m.Store.PutAnchor(an)
	if v, _ := m.VerifyAnchor(ctx, an.ID); v.RootOK {
		t.Fatal("tampered leaves must fail")
	}
}

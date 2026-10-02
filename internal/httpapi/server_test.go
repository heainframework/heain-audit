package httpapi

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/heainframework/heain-audit/internal/anchor"
	"github.com/heainframework/heain-audit/internal/anomaly"
	"github.com/heainframework/heain-audit/internal/auditwire"
	"github.com/heainframework/heain-audit/internal/ledger"
)

func generateSelfSignedIssuer(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "heain-audit test issuer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

func newTestServer(t *testing.T, withAnchor bool) *Server {
	t.Helper()
	l, err := ledger.Open(filepath.Join(t.TempDir(), "ledger.db"))
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	if !withAnchor {
		return NewServer(l, nil, nil, nil, nil)
	}

	certPEM, keyPEM := generateSelfSignedIssuer(t)
	signer, err := anchor.NewSigner(l, certPEM, keyPEM)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	ckptStore, err := anchor.OpenStore(filepath.Join(t.TempDir(), "checkpoints.db"))
	if err != nil {
		t.Fatalf("anchor.OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = ckptStore.Close() })

	return NewServer(l, signer, ckptStore, nil, nil)
}

func doJSON(t *testing.T, srv *Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func TestHandleEvents_PostThenGet(t *testing.T) {
	srv := newTestServer(t, false)

	w := doJSON(t, srv, http.MethodPost, "/events", auditwire.RecordEventRequest{
		Actor: "alice", Action: "login", Subject: "node-1",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /events status = %d, body = %s", w.Code, w.Body.String())
	}
	var created auditwire.EventResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if created.Sequence != 1 {
		t.Fatalf("Sequence = %d, want 1", created.Sequence)
	}

	w = doJSON(t, srv, http.MethodGet, "/events?from=1&to=1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /events status = %d, body = %s", w.Code, w.Body.String())
	}
	var list []auditwire.EventResponse
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(list) != 1 || list[0].Actor != "alice" {
		t.Fatalf("list = %+v", list)
	}
}

func TestHandleEvents_PostRejectsEmptyActor(t *testing.T) {
	srv := newTestServer(t, false)
	w := doJSON(t, srv, http.MethodPost, "/events", auditwire.RecordEventRequest{Action: "login"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandleVerify_ValidChain(t *testing.T) {
	srv := newTestServer(t, false)
	for i := 0; i < 3; i++ {
		doJSON(t, srv, http.MethodPost, "/events", auditwire.RecordEventRequest{Actor: "alice", Action: "a"})
	}
	w := doJSON(t, srv, http.MethodGet, "/verify?from=1&to=3", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp auditwire.VerifyChainResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.Valid {
		t.Fatalf("resp = %+v, want Valid=true", resp)
	}
}

func TestHandleCreateCheckpoint_DisabledReturns503(t *testing.T) {
	srv := newTestServer(t, false)
	doJSON(t, srv, http.MethodPost, "/events", auditwire.RecordEventRequest{Actor: "alice", Action: "a"})
	w := doJSON(t, srv, http.MethodPost, "/checkpoint?from=1&to=1", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestHandleCreateCheckpoint_ThenVerify(t *testing.T) {
	srv := newTestServer(t, true)
	for i := 0; i < 3; i++ {
		doJSON(t, srv, http.MethodPost, "/events", auditwire.RecordEventRequest{Actor: "alice", Action: "a"})
	}
	w := doJSON(t, srv, http.MethodPost, "/checkpoint?from=1&to=3", nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST /checkpoint status = %d, body = %s", w.Code, w.Body.String())
	}
	var ckpt auditwire.CheckpointResponse
	json.Unmarshal(w.Body.Bytes(), &ckpt)
	if ckpt.ID == "" {
		t.Fatal("checkpoint ID is empty")
	}

	w = doJSON(t, srv, http.MethodGet, "/verify-checkpoint/"+ckpt.ID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /verify-checkpoint status = %d, body = %s", w.Code, w.Body.String())
	}
	var verify auditwire.VerifyCheckpointResponse
	json.Unmarshal(w.Body.Bytes(), &verify)
	if !verify.Valid {
		t.Fatalf("verify = %+v, want Valid=true", verify)
	}

	w = doJSON(t, srv, http.MethodGet, "/checkpoints", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /checkpoints status = %d", w.Code)
	}
	var list []auditwire.CheckpointResponse
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Fatalf("len(list) = %d, want 1", len(list))
	}
}

func TestHandleVerifyCheckpoint_UnknownIDReturns404(t *testing.T) {
	srv := newTestServer(t, true)
	w := doJSON(t, srv, http.MethodGet, "/verify-checkpoint/does-not-exist", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestHandleListFlags_DisabledReturns503(t *testing.T) {
	srv := newTestServer(t, false)
	w := doJSON(t, srv, http.MethodGet, "/flags", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestRunAnomalyScoring_FlagsPersisted(t *testing.T) {
	l, err := ledger.Open(filepath.Join(t.TempDir(), "ledger.db"))
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	defer l.Close()
	for i := 0; i < 2; i++ {
		l.Append("alice", "action", "subject", nil)
	}

	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"flags": []anomaly.Flag{{Sequence: 2, Score: 0.8, Reason: "test"}},
		})
	}))
	defer sidecar.Close()

	flagStore, err := anomaly.OpenStore(filepath.Join(t.TempDir(), "flags.db"))
	if err != nil {
		t.Fatalf("anomaly.OpenStore: %v", err)
	}
	defer flagStore.Close()

	srv := NewServer(l, nil, nil, anomaly.NewClient(sidecar.URL), flagStore)
	if err := srv.RunAnomalyScoring(10); err != nil {
		t.Fatalf("RunAnomalyScoring: %v", err)
	}

	flags, err := flagStore.ListFlags()
	if err != nil {
		t.Fatalf("ListFlags: %v", err)
	}
	if len(flags) != 1 {
		t.Fatalf("len(flags) = %d, want 1", len(flags))
	}
}

func TestRunAnomalyScoring_NoopWhenNotConfigured(t *testing.T) {
	l, err := ledger.Open(filepath.Join(t.TempDir(), "ledger.db"))
	if err != nil {
		t.Fatalf("ledger.Open: %v", err)
	}
	defer l.Close()
	srv := NewServer(l, nil, nil, nil, nil)
	if err := srv.RunAnomalyScoring(10); err != nil {
		t.Fatalf("RunAnomalyScoring: %v", err)
	}
}

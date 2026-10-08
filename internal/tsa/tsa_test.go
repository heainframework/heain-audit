package tsa

import (
	"context"
	"crypto/sha256"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestStampAndVerify(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	ta := TestAuthority{Dir: t.TempDir()}
	if err := ta.Setup(); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(ta)
	defer srv.Close()
	d := sha256.Sum256([]byte("a checkpoint root"))
	tok, err := Stamp(context.Background(), srv.URL, d[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(tok.GenTime) > time.Minute || tok.Serial == "" {
		t.Fatalf("token: %+v", tok)
	}
	info, err := Parse(tok.DER)
	if err != nil || string(info.MessageImprint.HashedMessage) != string(d[:]) {
		t.Fatalf("parse: %v", err)
	}
	ca := filepath.Join(ta.Dir, "ca.pem")
	if err := Verify(tok.DER, d[:], ca); err != nil {
		t.Fatal(err)
	}
	other := sha256.Sum256([]byte("another root"))
	if err := Verify(tok.DER, other[:], ca); err == nil {
		t.Fatal("a token must not verify for another digest")
	}
	if _, err := Stamp(context.Background(), srv.URL, []byte("short"), nil); err == nil {
		t.Fatal("not a digest")
	}
}

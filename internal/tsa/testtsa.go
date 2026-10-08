package tsa

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

// TestAuthority is a TEST ONLY time-stamp authority: openssl ts -reply with a
// throwaway CA and TSA certificate made in Dir. It exists so the live tests
// and unit tests can stamp without reaching a real TSA.
type TestAuthority struct{ Dir string }

func run(dir string, args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", args, out)
	}
	return nil
}

// Setup makes the CA (ca.pem) and the TSA certificate once.
func (t TestAuthority) Setup() error {
	if _, err := os.Stat(filepath.Join(t.Dir, "tsa.pem")); err == nil {
		return nil
	}
	if err := os.MkdirAll(t.Dir, 0o700); err != nil {
		return err
	}
	cnf := `[ tsa ]
default_tsa = tsa_config1
[ tsa_config1 ]
serial = ./serial
crypto_device = builtin
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ordering = no
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
`
	ext := "extendedKeyUsage=critical,timeStamping\nkeyUsage=critical,digitalSignature\n"
	if err := os.WriteFile(filepath.Join(t.Dir, "tsa.cnf"), []byte(cnf), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(t.Dir, "serial"), []byte("01\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(t.Dir, "tsa.ext"), []byte(ext), 0o600); err != nil {
		return err
	}
	for _, c := range [][]string{
		{"openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "7", "-subj", "/CN=heain TEST ONLY tsa ca",
			"-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign"},
		{"openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "tsa.key", "-out", "tsa.csr", "-subj", "/CN=heain TEST ONLY tsa"},
		{"openssl", "x509", "-req", "-in", "tsa.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "tsa.pem", "-days", "7", "-extfile", "tsa.ext"},
	} {
		if err := run(t.Dir, c...); err != nil {
			return err
		}
	}
	return nil
}

// ServeHTTP answers an RFC 3161 query.
func (t TestAuthority) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil || r.Method != http.MethodPost {
		http.Error(w, "POST an RFC 3161 query", http.StatusBadRequest)
		return
	}
	f, err := os.CreateTemp(t.Dir, "q-*.tsq")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(f.Name())
	_, _ = f.Write(q)
	f.Close()
	out := f.Name() + ".tsr"
	defer os.Remove(out)
	if err := run(t.Dir, "openssl", "ts", "-reply", "-queryfile", f.Name(), "-config", "tsa.cnf", "-inkey", "tsa.key", "-signer", "tsa.pem", "-out", out); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp, err := os.ReadFile(out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/timestamp-reply")
	_, _ = w.Write(resp)
}

// Package anchor builds periodic, signed Merkle-root checkpoints over
// contiguous ranges of a ledger.Store's hash-chained events.
//
// The ledger's own hash chain (internal/ledger) already makes any edit to
// a past event detectable by recomputing the chain. What a hash chain
// alone cannot do is prove that heain-audit itself has not quietly
// recomputed and replaced the *entire* chain from some point onward
// (an operator with DB access could, in principle, tamper with an event
// and then regenerate every hash after it consistently). A checkpoint
// closes that gap: it signs a Merkle root over a batch of events with a
// key heain-audit holds, and -- critically -- that signed checkpoint is
// handed out immediately to its own append-only store the moment it is
// created. An auditor who collected checkpoints as they were issued over
// time, or who anchored the root somewhere independent (Stage B; see the
// design notes), can detect if the *live* ledger no longer reproduces an
// *earlier* checkpoint's root -- which a purely self-consistent rewritten
// chain would not reveal on its own.
//
// Stage A deliberately stops at "sign and store the checkpoint locally".
// Publishing the root somewhere outside heain-audit's own control (a
// public blockchain, a notary service) is real external anchoring and is
// explicitly deferred to Stage B.
package anchor

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/heainframework/heain-audit/internal/ledger"
)

// ErrNotFound is returned when a checkpoint lookup finds nothing.
var ErrNotFound = errors.New("anchor: checkpoint not found")

// Checkpoint is one signed Merkle-anchored attestation over
// [FromSequence, ToSequence] of the ledger.
type Checkpoint struct {
	ID            string    `json:"id"`
	FromSequence  uint64    `json:"from_sequence"`
	ToSequence    uint64    `json:"to_sequence"`
	MerkleRoot    string    `json:"merkle_root"`
	SignatureB64  string    `json:"signature_b64"`
	IssuerCertPEM string    `json:"issuer_cert_pem"`
	CreatedAt     time.Time `json:"created_at"`
}

// merkleRoot computes a simple binary Merkle root over a list of
// already-hex-encoded leaf hashes (the events' own Hash field). An odd
// node at any level is paired with itself, the common simplification for
// a Merkle tree over a non-power-of-two leaf count.
func merkleRoot(leafHexHashes []string) (string, error) {
	if len(leafHexHashes) == 0 {
		return "", errors.New("anchor: cannot compute a Merkle root over zero leaves")
	}
	level := make([][]byte, len(leafHexHashes))
	for i, h := range leafHexHashes {
		b, err := hex.DecodeString(h)
		if err != nil {
			return "", fmt.Errorf("anchor: leaf hash %q is not valid hex: %w", h, err)
		}
		level[i] = b
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			sum := sha256.Sum256(append(append([]byte{}, left...), right...))
			next = append(next, sum[:])
		}
		level = next
	}
	return hex.EncodeToString(level[0]), nil
}

// canonicalCheckpointSummary is the exact byte sequence that gets signed
// (and later re-verified). It deliberately mirrors
// heain-access's dcp_key Verifier's "sign a canonical summary" pattern.
func canonicalCheckpointSummary(c Checkpoint) []byte {
	return []byte(fmt.Sprintf(
		"heain-audit-checkpoint\x00from=%d\x00to=%d\x00root=%s\x00",
		c.FromSequence, c.ToSequence, c.MerkleRoot,
	))
}

// Signer builds and signs checkpoints over a ledger.Store using an RSA
// issuer key (RSA-PSS over SHA-256, the same primitive heain-access's
// dcp_key Verifier uses for KDM signatures).
type Signer struct {
	Ledger        *ledger.Store
	issuerKey     *rsa.PrivateKey
	issuerCertPEM string
}

// NewSigner parses the issuer certificate and private key (PEM, PKCS#1 or
// PKCS#8) and returns a ready-to-use Signer.
func NewSigner(l *ledger.Store, issuerCertPEM, issuerKeyPEM []byte) (*Signer, error) {
	certBlock, _ := pem.Decode(issuerCertPEM)
	if certBlock == nil {
		return nil, errors.New("anchor: failed to decode issuer certificate PEM")
	}
	if _, err := x509.ParseCertificate(certBlock.Bytes); err != nil {
		return nil, fmt.Errorf("anchor: issuer certificate is not a valid X.509 certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(issuerKeyPEM)
	if keyBlock == nil {
		return nil, errors.New("anchor: failed to decode issuer key PEM")
	}
	key, err := parseRSAPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("anchor: parsing issuer private key: %w", err)
	}

	return &Signer{Ledger: l, issuerKey: key, issuerCertPEM: string(issuerCertPEM)}, nil
}

func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("PKCS8 key is not an RSA key")
	}
	return key, nil
}

// CreateCheckpoint builds a Merkle root over [from, to] inclusive of the
// ledger, signs it, and returns the checkpoint. It does not persist the
// checkpoint itself -- that is the caller's (internal/httpapi's) job via
// a Store, so anchor stays a pure compute-and-sign package with no
// storage opinion of its own.
func (s *Signer) CreateCheckpoint(id string, from, to uint64) (Checkpoint, error) {
	events, err := s.Ledger.List(from, to)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("anchor: loading events: %w", err)
	}
	if len(events) == 0 {
		return Checkpoint{}, fmt.Errorf("anchor: no events in range [%d,%d]", from, to)
	}
	// List already returns events in ascending sequence order; sort
	// defensively anyway so the Merkle leaf order is never accidentally
	// storage-order-dependent.
	sort.Slice(events, func(i, j int) bool { return events[i].Sequence < events[j].Sequence })

	leaves := make([]string, len(events))
	for i, e := range events {
		leaves[i] = e.Hash
	}
	root, err := merkleRoot(leaves)
	if err != nil {
		return Checkpoint{}, err
	}

	c := Checkpoint{
		ID:            id,
		FromSequence:  events[0].Sequence,
		ToSequence:    events[len(events)-1].Sequence,
		MerkleRoot:    root,
		IssuerCertPEM: s.issuerCertPEM,
		CreatedAt:     time.Now().UTC(),
	}

	digest := sha256.Sum256(canonicalCheckpointSummary(c))
	sig, err := rsa.SignPSS(rand.Reader, s.issuerKey, crypto.SHA256, digest[:], nil)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("anchor: signing checkpoint: %w", err)
	}
	c.SignatureB64 = base64.StdEncoding.EncodeToString(sig)
	return c, nil
}

// VerifyCheckpoint independently recomputes the Merkle root over the
// checkpoint's own claimed [FromSequence, ToSequence] range (reading the
// *current* state of the ledger, not trusting the checkpoint's stored
// root) and re-verifies the signature against the issuer certificate
// embedded in the checkpoint itself. rootMatches is false if the live
// ledger no longer reproduces the checkpoint's root (meaning the ledger
// changed since the checkpoint was issued); sigValid is false if the
// signature does not verify against the stored root+range (meaning the
// checkpoint record itself was tampered with).
func VerifyCheckpoint(l *ledger.Store, c Checkpoint) (rootMatches bool, sigValid bool, err error) {
	events, err := l.List(c.FromSequence, c.ToSequence)
	if err != nil {
		return false, false, fmt.Errorf("anchor: loading events: %w", err)
	}
	leaves := make([]string, len(events))
	for i, e := range events {
		leaves[i] = e.Hash
	}
	recomputedRoot, err := merkleRoot(leaves)
	if err != nil {
		return false, false, err
	}
	rootMatches = recomputedRoot == c.MerkleRoot

	certBlock, _ := pem.Decode([]byte(c.IssuerCertPEM))
	if certBlock == nil {
		return rootMatches, false, errors.New("anchor: checkpoint's issuer certificate PEM is invalid")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return rootMatches, false, fmt.Errorf("anchor: parsing checkpoint's issuer certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return rootMatches, false, errors.New("anchor: checkpoint's issuer certificate does not hold an RSA key")
	}
	sig, err := base64.StdEncoding.DecodeString(c.SignatureB64)
	if err != nil {
		return rootMatches, false, fmt.Errorf("anchor: decoding signature: %w", err)
	}
	digest := sha256.Sum256(canonicalCheckpointSummary(c))
	sigErr := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, nil)
	sigValid = sigErr == nil
	return rootMatches, sigValid, nil
}

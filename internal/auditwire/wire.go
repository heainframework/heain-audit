// Package auditwire holds the HTTP wire types for heain-audit -- the
// tamper-evident, append-only audit log module. These are pure data
// shapes; the actual hash-chain and Merkle-anchoring logic live in
// internal/ledger and internal/anchor respectively.
package auditwire

import "time"

// RecordEventRequest is the body of POST /events.
type RecordEventRequest struct {
	Actor   string            `json:"actor"`
	Action  string            `json:"action"`
	Subject string            `json:"subject"`
	Details map[string]string `json:"details,omitempty"`
}

// EventResponse is one recorded, hash-chained audit event as returned to
// callers.
type EventResponse struct {
	Sequence  uint64            `json:"sequence"`
	Actor     string            `json:"actor"`
	Action    string            `json:"action"`
	Subject   string            `json:"subject"`
	Details   map[string]string `json:"details,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	PrevHash  string            `json:"prev_hash"`
	Hash      string            `json:"hash"`
}

// VerifyChainResponse is the result of GET /verify.
type VerifyChainResponse struct {
	Valid         bool   `json:"valid"`
	EventsChecked uint64 `json:"events_checked"`
	// BrokenAtSequence is set only when Valid is false: the sequence
	// number of the first event whose recomputed hash does not match
	// its stored hash (or whose stored PrevHash does not match the
	// previous event's stored hash).
	BrokenAtSequence uint64 `json:"broken_at_sequence,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

// CheckpointResponse is one signed Merkle-anchored checkpoint over a
// contiguous range of events, as returned by POST /checkpoint and
// GET /checkpoints.
type CheckpointResponse struct {
	ID            string    `json:"id"`
	FromSequence  uint64    `json:"from_sequence"`
	ToSequence    uint64    `json:"to_sequence"`
	MerkleRoot    string    `json:"merkle_root"`
	SignatureB64  string    `json:"signature_b64"`
	IssuerCertPEM string    `json:"issuer_cert_pem"`
	CreatedAt     time.Time `json:"created_at"`
}

// VerifyCheckpointResponse is the result of GET /verify-checkpoint/{id}:
// independently recomputes the Merkle root over the checkpoint's own
// claimed event range and re-verifies the signature, so a caller does not
// have to trust heain-audit's own say-so that the checkpoint is valid.
type VerifyCheckpointResponse struct {
	Valid                 bool   `json:"valid"`
	RecomputedRootMatches bool   `json:"recomputed_root_matches"`
	SignatureValid        bool   `json:"signature_valid"`
	Reason                string `json:"reason,omitempty"`
}

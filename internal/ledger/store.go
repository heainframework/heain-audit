// Package ledger implements heain-audit's core tamper-evident storage: an
// append-only, hash-chained sequence of audit events, backed by embedded
// BoltDB (the same convention used by heain-core/heain-job/heain-database
// for local, node-scoped state).
//
// Each event's Hash is SHA-256 over a canonical encoding of its own fields
// plus the previous event's Hash. This makes the log a simple hash chain:
// recomputing the chain from the start (VerifyChain) detects any edit,
// deletion, or reordering of a past event, because changing any one
// event's content changes its Hash, which changes every subsequent
// event's PrevHash-derived Hash as well.
//
// This is deliberately the simplest tamper-evidence primitive (a hash
// chain), not a cryptographic accumulator or blockchain. Batch Merkle
// anchoring (internal/anchor) builds on top of this ledger to let an
// independent, periodic signature attest to a whole batch's integrity
// without needing to trust heain-audit's own say-so of "nothing changed".
package ledger

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// ErrNotFound is returned when a lookup finds no matching event.
var ErrNotFound = errors.New("ledger: not found")

// GenesisHash is the PrevHash of the very first event in the chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000"

var bucketEvents = []byte("events")
var bucketMeta = []byte("meta")

var keyLastSequence = []byte("last_sequence")

// Event is one recorded, hash-chained audit entry.
type Event struct {
	Sequence  uint64            `json:"sequence"`
	Actor     string            `json:"actor"`
	Action    string            `json:"action"`
	Subject   string            `json:"subject"`
	Details   map[string]string `json:"details,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	PrevHash  string            `json:"prev_hash"`
	Hash      string            `json:"hash"`
}

// canonicalPayload returns the deterministic byte representation of an
// event's content (everything except Hash itself) that Hash is computed
// over. Details keys are sorted so the encoding never depends on Go map
// iteration order.
func canonicalPayload(e Event) []byte {
	keys := make([]string, 0, len(e.Details))
	for k := range e.Details {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	buf := make([]byte, 0, 256)
	buf = append(buf, []byte(fmt.Sprintf("seq=%d\x00", e.Sequence))...)
	buf = append(buf, []byte("actor="+e.Actor+"\x00")...)
	buf = append(buf, []byte("action="+e.Action+"\x00")...)
	buf = append(buf, []byte("subject="+e.Subject+"\x00")...)
	for _, k := range keys {
		buf = append(buf, []byte("detail:"+k+"="+e.Details[k]+"\x00")...)
	}
	buf = append(buf, []byte("ts="+e.Timestamp.UTC().Format(time.RFC3339Nano)+"\x00")...)
	buf = append(buf, []byte("prev="+e.PrevHash+"\x00")...)
	return buf
}

func computeHash(e Event) string {
	sum := sha256.Sum256(canonicalPayload(e))
	return hex.EncodeToString(sum[:])
}

// Store is a BoltDB-backed, hash-chained append-only event log.
type Store struct {
	db *bolt.DB
}

// Open opens (creating if necessary) the BoltDB file at path and ensures
// its buckets exist.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("ledger: open %s: %w", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketEvents); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(bucketMeta)
		return err
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ledger: init buckets: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying BoltDB handle.
func (s *Store) Close() error {
	return s.db.Close()
}

func sequenceKey(seq uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, seq)
	return b
}

// Append records a new event at the end of the chain, computing its
// PrevHash from the current last event (or GenesisHash if this is the
// first) and its own Hash from its content + PrevHash. The caller-supplied
// fields (actor/action/subject/details) are never mutated after this call
// -- timestamp, sequence, prev_hash, and hash are all assigned here.
func (s *Store) Append(actor, action, subject string, details map[string]string) (Event, error) {
	if actor == "" || action == "" {
		return Event{}, errors.New("ledger: actor and action must not be empty")
	}
	var e Event
	err := s.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		events := tx.Bucket(bucketEvents)

		var lastSeq uint64
		var prevHash string = GenesisHash
		if v := meta.Get(keyLastSequence); v != nil {
			lastSeq = binary.BigEndian.Uint64(v)
			raw := events.Get(sequenceKey(lastSeq))
			if raw == nil {
				return fmt.Errorf("ledger: corrupt state: last_sequence=%d has no event", lastSeq)
			}
			var prev Event
			if err := json.Unmarshal(raw, &prev); err != nil {
				return err
			}
			prevHash = prev.Hash
		}

		e = Event{
			Sequence:  lastSeq + 1,
			Actor:     actor,
			Action:    action,
			Subject:   subject,
			Details:   details,
			Timestamp: time.Now().UTC(),
			PrevHash:  prevHash,
		}
		e.Hash = computeHash(e)

		data, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if err := events.Put(sequenceKey(e.Sequence), data); err != nil {
			return err
		}
		newSeq := make([]byte, 8)
		binary.BigEndian.PutUint64(newSeq, e.Sequence)
		return meta.Put(keyLastSequence, newSeq)
	})
	return e, err
}

// Get returns the event at the given sequence number, or ErrNotFound.
func (s *Store) Get(seq uint64) (Event, error) {
	var e Event
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketEvents).Get(sequenceKey(seq))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &e)
	})
	return e, err
}

// LastSequence returns the sequence number of the most recently appended
// event, or 0 if the ledger is empty.
func (s *Store) LastSequence() (uint64, error) {
	var seq uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketMeta).Get(keyLastSequence)
		if v == nil {
			return nil
		}
		seq = binary.BigEndian.Uint64(v)
		return nil
	})
	return seq, err
}

// List returns events with sequence numbers in [from, to] inclusive, in
// ascending order. A from/to of 0 means "no lower/upper bound" is NOT
// supported here deliberately -- callers must pass real bounds (use
// LastSequence to find the upper bound), so a caller can never
// accidentally scan an unbounded, ever-growing table.
func (s *Store) List(from, to uint64) ([]Event, error) {
	if from == 0 || to == 0 || from > to {
		return nil, fmt.Errorf("ledger: invalid range [%d,%d]", from, to)
	}
	var out []Event
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketEvents)
		c := b.Cursor()
		for k, v := c.Seek(sequenceKey(from)); k != nil; k, v = c.Next() {
			seq := binary.BigEndian.Uint64(k)
			if seq > to {
				break
			}
			var e Event
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			out = append(out, e)
		}
		return nil
	})
	return out, err
}

// VerifyChain recomputes the hash chain over [from, to] inclusive and
// confirms every event's stored Hash matches its recomputed hash, and
// every event's stored PrevHash matches the previous event's stored Hash
// (or GenesisHash, for the first event in the whole ledger). It returns
// ok=false and the first broken sequence number the instant a mismatch is
// found, rather than continuing to scan a known-tampered range.
func (s *Store) VerifyChain(from, to uint64) (ok bool, brokenAt uint64, reason string, err error) {
	events, err := s.List(from, to)
	if err != nil {
		return false, 0, "", err
	}
	expectedPrev := GenesisHash
	if from > 1 {
		prevEvent, err := s.Get(from - 1)
		if err != nil {
			return false, 0, "", fmt.Errorf("ledger: cannot load event preceding range start: %w", err)
		}
		expectedPrev = prevEvent.Hash
	}
	for _, e := range events {
		if e.PrevHash != expectedPrev {
			return false, e.Sequence, "stored prev_hash does not match preceding event's hash", nil
		}
		recomputed := computeHash(e)
		if recomputed != e.Hash {
			return false, e.Sequence, "stored hash does not match recomputed hash", nil
		}
		expectedPrev = e.Hash
	}
	return true, 0, "", nil
}

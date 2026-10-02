package ledger

import (
	"encoding/json"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// tamperEvent directly rewrites a stored event's raw bytes, bypassing
// Append and its hash computation entirely -- simulating an administrator
// (or attacker) editing the underlying BoltDB file directly. mutate may
// change any field except Hash is intentionally left as whatever mutate
// leaves it, so these tests can exercise both "content changed, hash
// stale" and "prev_hash changed" tamper scenarios.
func tamperEvent(t *testing.T, s *Store, seq uint64, mutate func(*Event)) {
	t.Helper()
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketEvents)
		raw := b.Get(sequenceKey(seq))
		if raw == nil {
			t.Fatalf("tamperEvent: no event at seq %d", seq)
		}
		var e Event
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		mutate(&e)
		data, err := json.Marshal(e)
		if err != nil {
			return err
		}
		return b.Put(sequenceKey(seq), data)
	})
	if err != nil {
		t.Fatalf("tamperEvent: %v", err)
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ledger.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestAppendAssignsSequenceAndGenesisPrevHash(t *testing.T) {
	s := openTestStore(t)
	e, err := s.Append("alice", "login", "node-1", nil)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if e.Sequence != 1 {
		t.Fatalf("Sequence = %d, want 1", e.Sequence)
	}
	if e.PrevHash != GenesisHash {
		t.Fatalf("PrevHash = %q, want genesis", e.PrevHash)
	}
	if e.Hash == "" {
		t.Fatal("Hash is empty")
	}
}

func TestAppendChainsHashes(t *testing.T) {
	s := openTestStore(t)
	e1, _ := s.Append("alice", "login", "node-1", nil)
	e2, err := s.Append("bob", "logout", "node-1", map[string]string{"reason": "timeout"})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if e2.Sequence != 2 {
		t.Fatalf("Sequence = %d, want 2", e2.Sequence)
	}
	if e2.PrevHash != e1.Hash {
		t.Fatalf("PrevHash = %q, want %q", e2.PrevHash, e1.Hash)
	}
}

func TestAppendRejectsEmptyActorOrAction(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Append("", "login", "node-1", nil); err == nil {
		t.Fatal("expected error for empty actor")
	}
	if _, err := s.Append("alice", "", "node-1", nil); err == nil {
		t.Fatal("expected error for empty action")
	}
}

func TestGetNotFound(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Get(1); err != ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestListRejectsUnboundedRange(t *testing.T) {
	s := openTestStore(t)
	s.Append("alice", "login", "node-1", nil)
	if _, err := s.List(0, 1); err == nil {
		t.Fatal("expected error for from=0")
	}
	if _, err := s.List(1, 0); err == nil {
		t.Fatal("expected error for to=0")
	}
	if _, err := s.List(5, 1); err == nil {
		t.Fatal("expected error for from>to")
	}
}

func TestVerifyChainValidForUntamperedLedger(t *testing.T) {
	s := openTestStore(t)
	for i := 0; i < 5; i++ {
		if _, err := s.Append("alice", "action", "subject", nil); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	ok, brokenAt, reason, err := s.VerifyChain(1, 5)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !ok {
		t.Fatalf("VerifyChain reported broken at %d: %s", brokenAt, reason)
	}
}

func TestVerifyChainDetectsTamperedContent(t *testing.T) {
	s := openTestStore(t)
	for i := 0; i < 3; i++ {
		s.Append("alice", "action", "subject", nil)
	}
	// Directly corrupt event 2's Action in the underlying bucket, bypassing
	// Append entirely -- simulating an administrator editing the raw DB file.
	tamperEvent(t, s, 2, func(e *Event) { e.Action = "tampered" })

	ok, brokenAt, reason, err := s.VerifyChain(1, 3)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if ok {
		t.Fatal("VerifyChain reported ok=true for a tampered ledger")
	}
	if brokenAt != 2 {
		t.Fatalf("brokenAt = %d, want 2", brokenAt)
	}
	if reason == "" {
		t.Fatal("expected a non-empty reason")
	}
}

func TestVerifyChainDetectsDeletedEventEffect(t *testing.T) {
	s := openTestStore(t)
	for i := 0; i < 3; i++ {
		s.Append("alice", "action", "subject", nil)
	}
	// Overwrite event 2's PrevHash to something wrong, simulating a
	// reordering/splice attempt.
	tamperEvent(t, s, 2, func(e *Event) { e.PrevHash = "deadbeef" })

	ok, brokenAt, _, err := s.VerifyChain(1, 3)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if ok {
		t.Fatal("VerifyChain reported ok=true for a tampered ledger")
	}
	if brokenAt != 2 {
		t.Fatalf("brokenAt = %d, want 2", brokenAt)
	}
}

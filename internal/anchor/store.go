package anchor

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucketCheckpoints = []byte("checkpoints")

// Store persists issued checkpoints. This is a separate, append-style
// BoltDB bucket from the ledger itself -- checkpoints are never edited
// once written, only added, and that is enforced at the Save call site
// (internal/httpapi), not re-enforced here, matching the lighter-weight
// convention already used by heain-database's own stores.
type Store struct {
	db *bolt.DB
}

// OpenStore opens (creating if necessary) the BoltDB file at path and
// ensures its bucket exists.
func OpenStore(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("anchor: open %s: %w", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketCheckpoints)
		return err
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("anchor: init bucket: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying BoltDB handle.
func (s *Store) Close() error {
	return s.db.Close()
}

// Save persists a checkpoint under its ID.
func (s *Store) Save(c Checkpoint) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketCheckpoints).Put([]byte(c.ID), data)
	})
}

// Get returns the checkpoint with the given ID, or ErrNotFound.
func (s *Store) Get(id string) (Checkpoint, error) {
	var c Checkpoint
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketCheckpoints).Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &c)
	})
	return c, err
}

// List returns every stored checkpoint, in no particular order -- callers
// that need chronological order should sort by CreatedAt themselves.
func (s *Store) List() ([]Checkpoint, error) {
	var out []Checkpoint
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketCheckpoints).ForEach(func(_, v []byte) error {
			var c Checkpoint
			if err := json.Unmarshal(v, &c); err != nil {
				return err
			}
			out = append(out, c)
			return nil
		})
	})
	return out, err
}

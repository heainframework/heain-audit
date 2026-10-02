package anomaly

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucketFlags = []byte("flags")

// StoredFlag is a Flag plus the time it was recorded, persisted so
// callers can review past anomaly findings without re-scoring.
type StoredFlag struct {
	Flag
	FlaggedAt time.Time `json:"flagged_at"`
}

// Store persists anomaly flags, keyed by the flagged event's sequence
// number. A later flag for the same sequence overwrites the earlier one
// (the sidecar is expected to be re-run over overlapping windows as new
// events arrive, so the latest score for a given event is the one that
// matters).
type Store struct {
	db *bolt.DB
}

// OpenStore opens (creating if necessary) the BoltDB file at path.
func OpenStore(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("anomaly: open %s: %w", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketFlags)
		return err
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("anomaly: init bucket: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying BoltDB handle.
func (s *Store) Close() error {
	return s.db.Close()
}

func seqKey(seq uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, seq)
	return b
}

// SaveFlags persists a batch of flags, each under its own event
// sequence number.
func (s *Store) SaveFlags(flags []Flag) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketFlags)
		for _, f := range flags {
			sf := StoredFlag{Flag: f, FlaggedAt: time.Now().UTC()}
			data, err := json.Marshal(sf)
			if err != nil {
				return err
			}
			if err := b.Put(seqKey(f.Sequence), data); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListFlags returns every stored anomaly flag.
func (s *Store) ListFlags() ([]StoredFlag, error) {
	var out []StoredFlag
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketFlags).ForEach(func(_, v []byte) error {
			var sf StoredFlag
			if err := json.Unmarshal(v, &sf); err != nil {
				return err
			}
			out = append(out, sf)
			return nil
		})
	})
	return out, err
}

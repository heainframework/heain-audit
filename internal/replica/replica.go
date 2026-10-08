// Package replica is heain-audit's own copy of a node's audit chain: every
// link as core stored it (prev_hash, hash and core's ciphertext, which
// heain-audit cannot read) and the decrypted event, sealed under
// heain-audit's data key from core's KMS. It also keeps the signed
// checkpoints, anomaly flags and divergence alerts.
//
// Records are appended only if they extend the replica's chain exactly
// (the caller has verified them with heain.VerifyAuditRecords); the
// replica never changes a record it holds, so it is the reference against
// which a later rewrite of core's chain is detected.
package replica

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/heainframework/heain-sdk/heain"
)

var (
	bChain  = []byte("chain")
	bEvents = []byte("events")
	bCkpt   = []byte("checkpoints")
	bFlags  = []byte("flags")
	bAlerts = []byte("alerts")
	bMeta   = []byte("meta")
	// Stage B-1d
	bWitness = []byte("witness") // <node>/<checkpoint id> -> Witnessed
	bAnchors = []byte("anchors") // <anchor id> -> Anchor
	bSent    = []byte("sent")    // <checkpoint id> -> the zone Master that holds it
)

// ErrNotFound: no such record or checkpoint.
var ErrNotFound = errors.New("replica: not found")

// Link is a record's chain material.
type Link struct {
	Seq        uint64 `json:"seq"`
	PrevHash   string `json:"prev_hash"`
	Hash       string `json:"hash"`
	Ciphertext []byte `json:"ciphertext"`
}

// Checkpoint is a signed Merkle root over [From, To].
type Checkpoint struct {
	ID        string    `json:"id"`
	From      uint64    `json:"from"`
	To        uint64    `json:"to"`
	Root      string    `json:"root"`
	LastHash  string    `json:"last_hash"`
	Signature []byte    `json:"signature_b64"`
	CertPEM   string    `json:"cert_pem"`
	CreatedAt time.Time `json:"created_at"`
}

// Flag is one event the anomaly model scored as unusual.
type Flag struct {
	Seq      uint64             `json:"seq"`
	Score    float64            `json:"score"`
	Action   string             `json:"action"`
	Actor    string             `json:"actor"`
	Features map[string]float64 `json:"features"`
	RecordID string             `json:"record_id"`
	ActionID string             `json:"action_id,omitempty"`
	At       time.Time          `json:"at"`
}

// Alert is a divergence between core's chain and the replica.
type Alert struct {
	ID       string    `json:"id"`
	Seq      uint64    `json:"seq"`
	Reason   string    `json:"reason"`
	ActionID string    `json:"action_id,omitempty"`
	At       time.Time `json:"at"`
}

// Store is the replica database.
type Store struct {
	db *bolt.DB
	s  *heain.Sealer
}

// Open opens (creating if needed) the replica at path; events are sealed
// with s.
func Open(path string, s *heain.Sealer) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("replica: open %s: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bChain, bEvents, bCkpt, bFlags, bAlerts, bMeta, bWitness, bAnchors, bSent} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Store{db: db, s: s}, nil
}

// Close closes the file.
func (st *Store) Close() error { return st.db.Close() }

func key(seq uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], seq)
	return b[:]
}

func aad(seq uint64) []byte { return []byte(fmt.Sprintf("event/%d", seq)) }

// Head is the last record held (0, "" when empty).
func (st *Store) Head() (uint64, string) {
	var seq uint64
	var hash string
	_ = st.db.View(func(tx *bolt.Tx) error {
		k, v := tx.Bucket(bChain).Cursor().Last()
		if k == nil {
			return nil
		}
		var l Link
		if json.Unmarshal(v, &l) == nil {
			seq, hash = l.Seq, l.Hash
		}
		return nil
	})
	return seq, hash
}

// Append adds verified records that extend the replica.
func (st *Store) Append(recs []heain.AuditRecord) error {
	return st.db.Update(func(tx *bolt.Tx) error {
		c, e := tx.Bucket(bChain), tx.Bucket(bEvents)
		var lastSeq uint64
		lastHash := ""
		if k, v := c.Cursor().Last(); k != nil {
			var l Link
			_ = json.Unmarshal(v, &l)
			lastSeq, lastHash = l.Seq, l.Hash
		}
		for _, r := range recs {
			if r.Seq != lastSeq+1 || (lastSeq > 0 && r.PrevHash != lastHash) {
				return fmt.Errorf("replica: record %d does not extend the replica (head %d)", r.Seq, lastSeq)
			}
			lb, _ := json.Marshal(Link{Seq: r.Seq, PrevHash: r.PrevHash, Hash: r.Hash, Ciphertext: r.Ciphertext})
			if err := c.Put(key(r.Seq), lb); err != nil {
				return err
			}
			eb, _ := json.Marshal(r.Event)
			if err := e.Put(key(r.Seq), st.s.Seal(eb, aad(r.Seq))); err != nil {
				return err
			}
			lastSeq, lastHash = r.Seq, r.Hash
		}
		return nil
	})
}

// Link returns the chain material of seq.
func (st *Store) Link(seq uint64) (Link, error) {
	var l Link
	err := st.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bChain).Get(key(seq))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &l)
	})
	return l, err
}

// Hashes returns the chain hashes of [from, to].
func (st *Store) Hashes(from, to uint64) ([]string, error) {
	var out []string
	err := st.db.View(func(tx *bolt.Tx) error {
		cur := tx.Bucket(bChain).Cursor()
		for k, v := cur.Seek(key(from)); k != nil && binary.BigEndian.Uint64(k) <= to; k, v = cur.Next() {
			var l Link
			if err := json.Unmarshal(v, &l); err != nil {
				return err
			}
			out = append(out, l.Hash)
		}
		return nil
	})
	if err == nil && uint64(len(out)) != to-from+1 {
		return nil, fmt.Errorf("replica: range %d-%d is not complete", from, to)
	}
	return out, err
}

// Entry is one replica record for queries.
type Entry struct {
	Seq   uint64           `json:"seq"`
	Hash  string           `json:"hash"`
	Event heain.AuditEvent `json:"event"`
}

// Events returns up to limit records from seq from that match (empty
// filter = all).
func (st *Store) Events(from uint64, limit int, actor, action string) ([]Entry, error) {
	out := []Entry{}
	err := st.db.View(func(tx *bolt.Tx) error {
		c, e := tx.Bucket(bChain), tx.Bucket(bEvents)
		cur := c.Cursor()
		for k, v := cur.Seek(key(from)); k != nil && len(out) < limit; k, v = cur.Next() {
			var l Link
			if err := json.Unmarshal(v, &l); err != nil {
				return err
			}
			p, err := st.s.Open(e.Get(k), aad(l.Seq))
			if err != nil {
				return fmt.Errorf("replica: event %d: %w", l.Seq, err)
			}
			var ev heain.AuditEvent
			if err := json.Unmarshal(p, &ev); err != nil {
				return err
			}
			if (actor == "" || ev.Actor == actor) && (action == "" || ev.Action == action) {
				out = append(out, Entry{Seq: l.Seq, Hash: l.Hash, Event: ev})
			}
		}
		return nil
	})
	return out, err
}

func (st *Store) putJSON(b []byte, k string, v any, seal bool) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if seal {
		data = st.s.Seal(data, []byte(string(b)+"/"+k))
	}
	return st.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(b).Put([]byte(k), data) })
}

func (st *Store) list(b []byte, seal bool, fn func([]byte) error) error {
	return st.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(b).ForEach(func(k, v []byte) error {
			if seal {
				p, err := st.s.Open(v, []byte(string(b)+"/"+string(k)))
				if err != nil {
					return err
				}
				v = p
			}
			return fn(v)
		})
	})
}

// PutCheckpoint stores a checkpoint (by id, ordered by creation).
func (st *Store) PutCheckpoint(c Checkpoint) error { return st.putJSON(bCkpt, c.ID, c, false) }

// Checkpoints lists every checkpoint, oldest first.
func (st *Store) Checkpoints() ([]Checkpoint, error) {
	out := []Checkpoint{}
	err := st.list(bCkpt, false, func(v []byte) error {
		var c Checkpoint
		if err := json.Unmarshal(v, &c); err != nil {
			return err
		}
		out = append(out, c)
		return nil
	})
	return out, err
}

// Checkpoint reads one checkpoint.
func (st *Store) Checkpoint(id string) (Checkpoint, error) {
	var c Checkpoint
	err := st.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bCkpt).Get([]byte(id))
		if v == nil {
			return ErrNotFound
		}
		return json.Unmarshal(v, &c)
	})
	return c, err
}

// PutFlag stores an anomaly flag (sealed).
func (st *Store) PutFlag(f Flag) error {
	return st.putJSON(bFlags, fmt.Sprintf("%020d", f.Seq), f, true)
}

// Flags lists the flags, by sequence.
func (st *Store) Flags() ([]Flag, error) {
	out := []Flag{}
	err := st.list(bFlags, true, func(v []byte) error {
		var f Flag
		if err := json.Unmarshal(v, &f); err != nil {
			return err
		}
		out = append(out, f)
		return nil
	})
	return out, err
}

// PutAlert stores a divergence alert.
func (st *Store) PutAlert(a Alert) error { return st.putJSON(bAlerts, a.ID, a, false) }

// Alerts lists the divergence alerts.
func (st *Store) Alerts() ([]Alert, error) {
	out := []Alert{}
	err := st.list(bAlerts, false, func(v []byte) error {
		var a Alert
		if err := json.Unmarshal(v, &a); err != nil {
			return err
		}
		out = append(out, a)
		return nil
	})
	return out, err
}

// SetMeta / Meta keep small counters (e.g. the last scored sequence).
func (st *Store) SetMeta(k string, v uint64) error {
	return st.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bMeta).Put([]byte(k), key(v)) })
}

// Meta reads a counter (0 if unset).
func (st *Store) Meta(k string) uint64 {
	var n uint64
	_ = st.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bMeta).Get([]byte(k)); len(v) == 8 {
			n = binary.BigEndian.Uint64(v)
		}
		return nil
	})
	return n
}

// ---- Stage B-1d: checkpoints witnessed for other nodes, anchors

// Witnessed (sealed at rest) is a checkpoint another node's heain-audit sent to this one
// (the heain-audit of its zone Master): roots only, never events.
type Witnessed struct {
	Node       string     `json:"node"`
	Checkpoint Checkpoint `json:"checkpoint"`
	From       string     `json:"from"` // the sending instance
	ReceivedAt time.Time  `json:"received_at"`
}

// PutWitnessed stores a received checkpoint.
func (st *Store) PutWitnessed(w Witnessed) error {
	return st.putJSON(bWitness, w.Node+"/"+w.Checkpoint.ID, w, true)
}

// WitnessedFor lists what node sent (every node when node is ""), oldest first.
func (st *Store) WitnessedFor(node string) ([]Witnessed, error) {
	out := []Witnessed{}
	err := st.list(bWitness, true, func(v []byte) error {
		var w Witnessed
		if err := json.Unmarshal(v, &w); err != nil {
			return err
		}
		if node == "" || w.Node == node {
			out = append(out, w)
		}
		return nil
	})
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Node != out[j].Node {
			return out[i].Node < out[j].Node
		}
		return out[i].Checkpoint.From < out[j].Checkpoint.From
	})
	return out, err
}

// MarkSent records that checkpoint id is held by the zone Master master.
func (st *Store) MarkSent(id, master string) error {
	return st.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bSent).Put([]byte(id), []byte(master)) })
}

// SentTo returns where checkpoint id was sent ("" = not yet).
func (st *Store) SentTo(id string) string {
	var m string
	_ = st.db.View(func(tx *bolt.Tx) error {
		m = string(tx.Bucket(bSent).Get([]byte(id)))
		return nil
	})
	return m
}

// Leaf is one checkpoint covered by an anchor.
type Leaf struct {
	Node       string `json:"node"`
	Checkpoint string `json:"checkpoint"`
	Digest     string `json:"digest"` // hex SHA-256 the checkpoint's signature covers
}

// Anchor is a Merkle root over checkpoint digests, stamped by a TSA (RFC 3161).
type Anchor struct {
	ID       string    `json:"id"`
	Root     string    `json:"root"`
	Leaves   []Leaf    `json:"leaves"`
	TSA      string    `json:"tsa"`
	Token    []byte    `json:"token_b64"`
	GenTime  time.Time `json:"gen_time"`
	Serial   string    `json:"serial"`
	Recorded time.Time `json:"recorded"`
}

// PutAnchor stores an anchor.
func (st *Store) PutAnchor(a Anchor) error { return st.putJSON(bAnchors, a.ID, a, true) }

// Anchors lists every anchor, oldest first.
func (st *Store) Anchors() ([]Anchor, error) {
	out := []Anchor{}
	err := st.list(bAnchors, true, func(v []byte) error {
		var a Anchor
		if err := json.Unmarshal(v, &a); err != nil {
			return err
		}
		out = append(out, a)
		return nil
	})
	return out, err
}

// Anchor reads one anchor.
func (st *Store) Anchor(id string) (Anchor, error) {
	var a Anchor
	err := st.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bAnchors).Get([]byte(id))
		if v == nil {
			return ErrNotFound
		}
		p, err := st.s.Open(v, []byte(string(bAnchors)+"/"+id))
		if err != nil {
			return err
		}
		return json.Unmarshal(p, &a)
	})
	return a, err
}

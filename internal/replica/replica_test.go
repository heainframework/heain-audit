package replica

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/heainframework/heain-sdk/heain"
)

func chain(from uint64, prev []byte, n int) ([]heain.AuditRecord, []byte) {
	var out []heain.AuditRecord
	for i := 0; i < n; i++ {
		seq := from + uint64(i)
		ct := []byte{byte(seq), 1, 2, 3}
		h := heain.AuditChainHash(prev, seq, ct)
		out = append(out, heain.AuditRecord{Seq: seq, PrevHash: hex.EncodeToString(prev), Hash: hex.EncodeToString(h), Ciphertext: ct,
			Event: heain.AuditEvent{Timestamp: time.Unix(int64(seq), 0).UTC(), Actor: "app.a1", Action: "secret-action-name", Detail: map[string]any{"n": float64(seq)}}})
		prev = h
	}
	return out, prev
}

func TestReplica(t *testing.T) {
	s, _ := heain.NewSealer(bytes.Repeat([]byte{4}, 32))
	p := filepath.Join(t.TempDir(), "r.db")
	st, err := Open(p, s)
	if err != nil {
		t.Fatal(err)
	}
	recs, last := chain(1, make([]byte, 32), 5)
	if err := st.Append(recs); err != nil {
		t.Fatal(err)
	}
	if seq, h := st.Head(); seq != 5 || h != hex.EncodeToString(last) {
		t.Fatal("head")
	}
	more, _ := chain(6, last, 2)
	if err := st.Append(more); err != nil {
		t.Fatal(err)
	}
	bad, _ := chain(8, make([]byte, 32), 1)
	if st.Append(bad) == nil {
		t.Fatal("a record that does not extend the replica must be refused")
	}
	if hs, err := st.Hashes(2, 4); err != nil || len(hs) != 3 || hs[0] != recs[1].Hash {
		t.Fatal("hashes")
	}
	if _, err := st.Hashes(5, 9); err == nil {
		t.Fatal("incomplete range")
	}
	if ev, _ := st.Events(1, 3, "", ""); len(ev) != 3 || ev[2].Event.Detail["n"] != float64(3) {
		t.Fatal("events")
	}
	_ = st.PutFlag(Flag{Seq: 3, Score: 0.8, Action: "secret-action-name"})
	_ = st.PutCheckpoint(Checkpoint{ID: "c1", From: 1, To: 5})
	_ = st.PutAlert(Alert{ID: "a1", Seq: 4, Reason: "x"})
	_ = st.SetMeta("scored", 7)
	f, _ := st.Flags()
	c, _ := st.Checkpoints()
	a, _ := st.Alerts()
	if len(f) != 1 || len(c) != 1 || len(a) != 1 || st.Meta("scored") != 7 {
		t.Fatal("side stores")
	}
	_ = st.Close()
	raw, _ := os.ReadFile(p)
	if bytes.Contains(raw, []byte("secret-action-name")) {
		t.Fatal("events and flags are sealed at rest")
	}
}

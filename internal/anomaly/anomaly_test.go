package anomaly

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/heainframework/heain-audit/internal/ledger"
)

func TestScoreBatch_EmptyEventsReturnsNoFlagsWithoutCallingSidecar(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	flags, err := c.ScoreBatch(context.Background(), nil)
	if err != nil {
		t.Fatalf("ScoreBatch: %v", err)
	}
	if flags != nil {
		t.Fatalf("flags = %v, want nil", flags)
	}
	if called {
		t.Fatal("sidecar was called for an empty event batch")
	}
}

func TestScoreBatch_ReturnsFlagsFromSidecar(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req scoreRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decoding request: %v", err)
		}
		if len(req.Events) != 2 {
			t.Fatalf("len(req.Events) = %d, want 2", len(req.Events))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(scoreResponse{
			Flags: []Flag{{Sequence: 2, Score: 0.91, Reason: "unusual timing gap"}},
		})
	}))
	defer srv.Close()

	events := []ledger.Event{
		{Sequence: 1, Actor: "alice", Action: "login", Timestamp: time.Now()},
		{Sequence: 2, Actor: "alice", Action: "delete_all", Timestamp: time.Now()},
	}
	c := NewClient(srv.URL)
	flags, err := c.ScoreBatch(context.Background(), events)
	if err != nil {
		t.Fatalf("ScoreBatch: %v", err)
	}
	if len(flags) != 1 || flags[0].Sequence != 2 {
		t.Fatalf("flags = %+v, want one flag for sequence 2", flags)
	}
}

func TestScoreBatch_SidecarErrorIsReturnedAsGoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(scoreResponse{Error: "model not loaded"})
	}))
	defer srv.Close()

	events := []ledger.Event{{Sequence: 1, Actor: "alice", Action: "login", Timestamp: time.Now()}}
	c := NewClient(srv.URL)
	_, err := c.ScoreBatch(context.Background(), events)
	if err == nil {
		t.Fatal("expected an error when the sidecar returns HTTP 500")
	}
}

func TestScoreBatch_UnreachableSidecarIsReturnedAsGoError(t *testing.T) {
	c := NewClient("http://127.0.0.1:1") // nothing listens here
	events := []ledger.Event{{Sequence: 1, Actor: "alice", Action: "login", Timestamp: time.Now()}}
	_, err := c.ScoreBatch(context.Background(), events)
	if err == nil {
		t.Fatal("expected an error for an unreachable sidecar")
	}
}

func TestFlagStore_SaveAndList(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "flags.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer s.Close()

	if err := s.SaveFlags([]Flag{
		{Sequence: 1, Score: 0.5, Reason: "a"},
		{Sequence: 2, Score: 0.9, Reason: "b"},
	}); err != nil {
		t.Fatalf("SaveFlags: %v", err)
	}
	flags, err := s.ListFlags()
	if err != nil {
		t.Fatalf("ListFlags: %v", err)
	}
	if len(flags) != 2 {
		t.Fatalf("len(flags) = %d, want 2", len(flags))
	}
}

func TestFlagStore_LaterFlagOverwritesEarlierForSameSequence(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "flags.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer s.Close()

	s.SaveFlags([]Flag{{Sequence: 1, Score: 0.1, Reason: "first pass"}})
	s.SaveFlags([]Flag{{Sequence: 1, Score: 0.95, Reason: "second pass"}})

	flags, err := s.ListFlags()
	if err != nil {
		t.Fatalf("ListFlags: %v", err)
	}
	if len(flags) != 1 {
		t.Fatalf("len(flags) = %d, want 1", len(flags))
	}
	if flags[0].Reason != "second pass" {
		t.Fatalf("Reason = %q, want %q", flags[0].Reason, "second pass")
	}
}

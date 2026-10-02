// Package httpapi ties heain-audit's ledger, checkpoint anchoring, and
// anomaly scoring into a single HTTP server.
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/heainframework/heain-audit/internal/anchor"
	"github.com/heainframework/heain-audit/internal/anomaly"
	"github.com/heainframework/heain-audit/internal/auditwire"
	"github.com/heainframework/heain-audit/internal/ledger"
)

// Server wires the ledger, optional checkpoint signer/store, and optional
// anomaly client/store into HTTP handlers. Checkpointing and anomaly
// scoring are both optional (nil Signer/AnomalyClient disables their
// endpoints with a 503) so a minimal deployment can run the hash-chained
// ledger alone.
type Server struct {
	Ledger          *ledger.Store
	Signer          *anchor.Signer
	CheckpointStore *anchor.Store
	AnomalyClient   *anomaly.Client
	FlagStore       *anomaly.Store

	mux *http.ServeMux
}

// NewServer builds a Server and registers its routes.
func NewServer(l *ledger.Store, signer *anchor.Signer, ckptStore *anchor.Store, anomalyClient *anomaly.Client, flagStore *anomaly.Store) *Server {
	s := &Server{
		Ledger:          l,
		Signer:          signer,
		CheckpointStore: ckptStore,
		AnomalyClient:   anomalyClient,
		FlagStore:       flagStore,
		mux:             http.NewServeMux(),
	}
	s.routes()
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("/events", s.handleEvents)
	s.mux.HandleFunc("/verify", s.handleVerify)
	s.mux.HandleFunc("/checkpoint", s.handleCreateCheckpoint)
	s.mux.HandleFunc("/checkpoints", s.handleListCheckpoints)
	s.mux.HandleFunc("/verify-checkpoint/", s.handleVerifyCheckpoint)
	s.mux.HandleFunc("/flags", s.handleListFlags)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func toEventResponse(e ledger.Event) auditwire.EventResponse {
	return auditwire.EventResponse{
		Sequence:  e.Sequence,
		Actor:     e.Actor,
		Action:    e.Action,
		Subject:   e.Subject,
		Details:   e.Details,
		Timestamp: e.Timestamp,
		PrevHash:  e.PrevHash,
		Hash:      e.Hash,
	}
}

// handleEvents: POST /events appends a new event; GET /events?from=&to=
// lists a range.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req auditwire.RecordEventRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}
		e, err := s.Ledger.Append(req.Actor, req.Action, req.Subject, req.Details)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, toEventResponse(e))
	case http.MethodGet:
		from, to, ok := parseRange(w, r)
		if !ok {
			return
		}
		events, err := s.Ledger.List(from, to)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		out := make([]auditwire.EventResponse, len(events))
		for i, e := range events {
			out[i] = toEventResponse(e)
		}
		writeJSON(w, http.StatusOK, out)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func parseRange(w http.ResponseWriter, r *http.Request) (from, to uint64, ok bool) {
	q := r.URL.Query()
	fromStr, toStr := q.Get("from"), q.Get("to")
	if fromStr == "" || toStr == "" {
		writeError(w, http.StatusBadRequest, "from and to query parameters are both required")
		return 0, 0, false
	}
	var err error
	from, err = strconv.ParseUint(fromStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid from: "+err.Error())
		return 0, 0, false
	}
	to, err = strconv.ParseUint(toStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid to: "+err.Error())
		return 0, 0, false
	}
	return from, to, true
}

// handleVerify: GET /verify?from=&to= recomputes the hash chain over a
// range and reports whether it is intact.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	from, to, ok := parseRange(w, r)
	if !ok {
		return
	}
	valid, brokenAt, reason, err := s.Ledger.VerifyChain(from, to)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := auditwire.VerifyChainResponse{Valid: valid, EventsChecked: to - from + 1}
	if !valid {
		resp.BrokenAtSequence = brokenAt
		resp.Reason = reason
	}
	writeJSON(w, http.StatusOK, resp)
}

func newCheckpointID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "ckpt-" + hex.EncodeToString(b), nil
}

func toCheckpointResponse(c anchor.Checkpoint) auditwire.CheckpointResponse {
	return auditwire.CheckpointResponse{
		ID:            c.ID,
		FromSequence:  c.FromSequence,
		ToSequence:    c.ToSequence,
		MerkleRoot:    c.MerkleRoot,
		SignatureB64:  c.SignatureB64,
		IssuerCertPEM: c.IssuerCertPEM,
		CreatedAt:     c.CreatedAt,
	}
}

// handleCreateCheckpoint: POST /checkpoint?from=&to= creates and signs a
// new checkpoint. Returns 503 if no Signer is configured.
func (s *Server) handleCreateCheckpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Signer == nil || s.CheckpointStore == nil {
		writeError(w, http.StatusServiceUnavailable, "checkpoint anchoring is not configured on this node")
		return
	}
	from, to, ok := parseRange(w, r)
	if !ok {
		return
	}
	id, err := newCheckpointID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "generating checkpoint id: "+err.Error())
		return
	}
	c, err := s.Signer.CreateCheckpoint(id, from, to)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.CheckpointStore.Save(c); err != nil {
		writeError(w, http.StatusInternalServerError, "saving checkpoint: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, toCheckpointResponse(c))
}

// handleListCheckpoints: GET /checkpoints.
func (s *Server) handleListCheckpoints(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.CheckpointStore == nil {
		writeError(w, http.StatusServiceUnavailable, "checkpoint anchoring is not configured on this node")
		return
	}
	checkpoints, err := s.CheckpointStore.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]auditwire.CheckpointResponse, len(checkpoints))
	for i, c := range checkpoints {
		out[i] = toCheckpointResponse(c)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleVerifyCheckpoint: GET /verify-checkpoint/{id} independently
// recomputes the checkpoint's Merkle root against the live ledger and
// re-verifies its signature.
func (s *Server) handleVerifyCheckpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.CheckpointStore == nil {
		writeError(w, http.StatusServiceUnavailable, "checkpoint anchoring is not configured on this node")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/verify-checkpoint/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "checkpoint id is required")
		return
	}
	c, err := s.CheckpointStore.Get(id)
	if err != nil {
		if err == anchor.ErrNotFound {
			writeError(w, http.StatusNotFound, "checkpoint not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rootMatches, sigValid, err := anchor.VerifyCheckpoint(s.Ledger, c)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := auditwire.VerifyCheckpointResponse{
		Valid:                 rootMatches && sigValid,
		RecomputedRootMatches: rootMatches,
		SignatureValid:        sigValid,
	}
	if !resp.Valid {
		switch {
		case !sigValid:
			resp.Reason = "signature does not verify against the stored checkpoint fields"
		case !rootMatches:
			resp.Reason = "the live ledger no longer reproduces this checkpoint's Merkle root"
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleListFlags: GET /flags lists stored anomaly flags. Returns 503 if
// no FlagStore is configured.
func (s *Server) handleListFlags(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.FlagStore == nil {
		writeError(w, http.StatusServiceUnavailable, "anomaly detection is not configured on this node")
		return
	}
	flags, err := s.FlagStore.ListFlags()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, flags)
}

// RunAnomalyScoring scores the most recent window of events (the last
// windowSize events, or fewer if the ledger is shorter) and persists any
// flags. Intended to be called periodically by cmd/heain-audit's
// background loop; errors are returned to the caller to log, never
// propagated anywhere that could affect the ledger's own write path.
func (s *Server) RunAnomalyScoring(windowSize uint64) error {
	if s.AnomalyClient == nil || s.FlagStore == nil {
		return nil
	}
	last, err := s.Ledger.LastSequence()
	if err != nil || last == 0 {
		return err
	}
	from := uint64(1)
	if last > windowSize {
		from = last - windowSize + 1
	}
	events, err := s.Ledger.List(from, last)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	flags, err := s.AnomalyClient.ScoreBatch(ctx, events)
	if err != nil {
		return err
	}
	if len(flags) == 0 {
		return nil
	}
	return s.FlagStore.SaveFlags(flags)
}

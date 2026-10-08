package api

// Stage B-1d endpoints: witnessed checkpoints and RFC 3161 anchors.

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/heainframework/heain-sdk/heain"

	"github.com/heainframework/heain-audit/internal/auditor"
	"github.com/heainframework/heain-audit/internal/replica"
)

func (a *API) witness(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Node       string             `json:"node"`
		Checkpoint replica.Checkpoint `json:"checkpoint"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&q); err != nil {
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	var cert []byte
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert = r.TLS.PeerCertificates[0].Raw
	}
	got, err := a.A.Witness(r.Context(), heain.Caller(r.Context()), cert, q.Node, q.Checkpoint)
	switch {
	case errors.Is(err, auditor.ErrConflict):
		fail(w, http.StatusConflict, "checkpoint_conflict", err.Error())
	case err != nil:
		fail(w, http.StatusForbidden, "refused", err.Error())
	default:
		reply(w, http.StatusOK, got)
	}
}

func (a *API) witnessed(w http.ResponseWriter, r *http.Request) {
	ws, err := a.A.Store.WitnessedFor(r.URL.Query().Get("node"))
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	reply(w, http.StatusOK, map[string]any{"witnessed": ws})
}

func (a *API) anchorNow(w http.ResponseWriter, r *http.Request) {
	an, err := a.A.Anchor(r.Context())
	switch {
	case errors.Is(err, auditor.ErrNothingNew):
		fail(w, http.StatusConflict, "nothing_new", "every checkpoint held here is anchored already")
	case errors.Is(err, auditor.ErrNoAnchoring):
		fail(w, http.StatusServiceUnavailable, "no_tsa", err.Error())
	case err != nil:
		fail(w, http.StatusBadGateway, "tsa_failed", err.Error())
	default:
		reply(w, http.StatusCreated, an)
	}
}

func (a *API) anchors(w http.ResponseWriter, r *http.Request) {
	as, err := a.A.Store.Anchors()
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	reply(w, http.StatusOK, map[string]any{"anchors": as})
}

func (a *API) anchorVerify(w http.ResponseWriter, r *http.Request) {
	v, err := a.A.VerifyAnchor(r.Context(), r.PathValue("id"))
	if errors.Is(err, replica.ErrNotFound) {
		fail(w, http.StatusNotFound, "not_found", "no such anchor")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	reply(w, http.StatusOK, v)
}

// anchorToken returns the TSA's token as it is (DER), for openssl ts -verify.
func (a *API) anchorToken(w http.ResponseWriter, r *http.Request) {
	an, err := a.A.Store.Anchor(r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusNotFound, "not_found", "no such anchor")
		return
	}
	w.Header().Set("Content-Type", "application/timestamp-reply")
	w.Header().Set("X-Heain-Anchor-Root", an.Root)
	_, _ = w.Write(an.Token)
}

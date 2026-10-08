// Package api serves heain-audit's capabilities over the heain-sdk
// direct-endpoint server (mTLS, app certificates, formal audit in core).
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/heainframework/heain-audit/internal/auditor"
	"github.com/heainframework/heain-audit/internal/replica"
	"github.com/heainframework/heain-sdk/heain"
)

// API ties the auditor to the endpoints.
type API struct{ A *auditor.Auditor }

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	reply(w, status, map[string]any{"error": map[string]any{"code": code, "message": msg, "retryable": status >= 500}})
}

// Register adds every endpoint of the manifest to s.
func (a *API) Register(s *heain.Server) error {
	for p, f := range map[string]http.HandlerFunc{
		"GET /v1/status":                  a.status,
		"GET /v1/records":                 a.records,
		"GET /v1/anomalies":               a.anomalies,
		"GET /v1/alerts":                  a.alerts,
		"POST /v1/checkpoints":            a.checkpoint,
		"GET /v1/checkpoints":             a.checkpoints,
		"GET /v1/checkpoints/{id}/verify": a.verify,
		"POST /v1/anomaly/scan":           a.scan,
		"POST /v1/witness/checkpoints":    a.witness,
		"GET /v1/witness/checkpoints":     a.witnessed,
		"POST /v1/anchors":                a.anchorNow,
		"GET /v1/anchors":                 a.anchors,
		"GET /v1/anchors/{id}/verify":     a.anchorVerify,
		"GET /v1/anchors/{id}/token":      a.anchorToken,
	} {
		if err := s.HandleFunc(p, f); err != nil {
			return err
		}
	}
	return nil
}

func (a *API) status(w http.ResponseWriter, r *http.Request) { reply(w, http.StatusOK, a.A.Status()) }

func (a *API) records(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from, _ := strconv.ParseUint(q.Get("from"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	es, err := a.A.Store.Events(from, limit, q.Get("actor"), q.Get("action"))
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	reply(w, http.StatusOK, map[string]any{"records": es})
}

func (a *API) anomalies(w http.ResponseWriter, r *http.Request) {
	fl, err := a.A.Store.Flags()
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	reply(w, http.StatusOK, map[string]any{"flags": fl})
}

func (a *API) alerts(w http.ResponseWriter, r *http.Request) {
	al, err := a.A.Store.Alerts()
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	reply(w, http.StatusOK, map[string]any{"alerts": al})
}

func (a *API) checkpoint(w http.ResponseWriter, r *http.Request) {
	c, err := a.A.Checkpoint(r.Context())
	if errors.Is(err, auditor.ErrNothingNew) {
		fail(w, http.StatusConflict, "nothing_new", err.Error())
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	reply(w, http.StatusCreated, c)
}

func (a *API) checkpoints(w http.ResponseWriter, r *http.Request) {
	cs, err := a.A.Store.Checkpoints()
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	reply(w, http.StatusOK, map[string]any{"checkpoints": cs})
}

func (a *API) verify(w http.ResponseWriter, r *http.Request) {
	v, err := a.A.Verify(r.Context(), r.PathValue("id"))
	if errors.Is(err, replica.ErrNotFound) {
		fail(w, http.StatusNotFound, "not_found", "no such checkpoint")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	reply(w, http.StatusOK, v)
}

func (a *API) scan(w http.ResponseWriter, r *http.Request) {
	if err := a.A.Pull(r.Context()); err != nil {
		// a divergence is reported in status/alerts; the scan still runs on the replica
		_ = err
	}
	sc, err := a.A.ScanNow(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	reply(w, http.StatusOK, sc)
}

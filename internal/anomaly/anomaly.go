// Package anomaly calls heain-audit's AI/ML sidecar to score a batch of
// recent events for anomalous patterns (unusual timing, unusual
// actor/action/subject sequences). This is heain-audit's required-AI/ML
// capability (the module's confirmed exception, alongside heain-job and
// heain-access) -- but it is deliberately advisory-only: a scoring
// failure or a flagged anomaly never blocks ledger.Store.Append or any
// other write path. The audit trail's correctness depends only on the
// deterministic hash chain (internal/ledger) and the signed Merkle
// checkpoints (internal/anchor); anomaly scoring exists purely to surface
// patterns a human reviewer should look at sooner rather than later.
package anomaly

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/heainframework/heain-audit/internal/ledger"
)

// DefaultTimeout bounds how long a scoring call is allowed to take before
// it is treated as a (non-fatal) failure.
const DefaultTimeout = 30 * time.Second

// EventFeature is the per-event shape sent to the sidecar -- a reduced
// view of ledger.Event, deliberately excluding Hash/PrevHash (the model
// scores behavioral patterns, not cryptographic material).
type EventFeature struct {
	Sequence  uint64 `json:"sequence"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Subject   string `json:"subject"`
	Timestamp string `json:"timestamp"`
}

// Flag is one anomalous sequence number the sidecar flagged, with a score
// and a human-readable reason.
type Flag struct {
	Sequence uint64  `json:"sequence"`
	Score    float64 `json:"score"`
	Reason   string  `json:"reason"`
}

type scoreRequest struct {
	Events []EventFeature `json:"events"`
}

type scoreResponse struct {
	Flags []Flag `json:"flags"`
	Error string `json:"error,omitempty"`
}

// Client calls the anomaly-detection sidecar over plain internal HTTP,
// matching the Python-sidecar architecture already established by
// heain-image/heain-videos/heain-sd/heain-access.
type Client struct {
	SidecarURL string
	HTTPClient *http.Client
}

// NewClient returns a Client with a sensible default timeout.
func NewClient(sidecarURL string) *Client {
	return &Client{
		SidecarURL: sidecarURL,
		HTTPClient: &http.Client{Timeout: DefaultTimeout},
	}
}

func toFeatures(events []ledger.Event) []EventFeature {
	out := make([]EventFeature, len(events))
	for i, e := range events {
		out[i] = EventFeature{
			Sequence:  e.Sequence,
			Actor:     e.Actor,
			Action:    e.Action,
			Subject:   e.Subject,
			Timestamp: e.Timestamp.UTC().Format(time.RFC3339Nano),
		}
	}
	return out
}

// ScoreBatch sends a batch of events to the sidecar and returns any
// flagged anomalies. A sidecar error or unreachable sidecar is returned
// as a Go error -- callers (internal/httpapi's background scorer) treat
// this as "scoring unavailable right now", never as a reason to fail the
// underlying audit write.
func (c *Client) ScoreBatch(ctx context.Context, events []ledger.Event) ([]Flag, error) {
	if len(events) == 0 {
		return nil, nil
	}
	reqBody, err := json.Marshal(scoreRequest{Events: toFeatures(events)})
	if err != nil {
		return nil, fmt.Errorf("anomaly: marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.SidecarURL+"/score", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("anomaly: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anomaly: calling sidecar: %w", err)
	}
	defer resp.Body.Close()

	var out scoreResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("anomaly: decoding sidecar response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anomaly: sidecar returned HTTP %d: %s", resp.StatusCode, out.Error)
	}
	if out.Error != "" {
		return nil, fmt.Errorf("anomaly: sidecar error: %s", out.Error)
	}
	return out.Flags, nil
}

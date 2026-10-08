package auditor

// Stage B-3a (author decisions 2026-10-08): the sequence model -- what each
// actor usually does next -- beside the Isolation Forest, which scores one
// event at a time. Its own capability (audit.sequence) and reasoning
// record, so each record names the model that decided; advisory, like the
// forest: flagged events go to the same P5 review.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	"github.com/heainframework/heain-sdk/heain"

	"github.com/heainframework/heain-audit/internal/replica"
	"github.com/heainframework/heain-audit/internal/seqmodel"
)

// SeqScan is the sequence model's part of a scan.
type SeqScan struct {
	History       int     `json:"history_events"`
	Vocabulary    int     `json:"vocabulary"`
	Scored        int     `json:"scored"`
	Flagged       int     `json:"flagged"`
	MaxBits       float64 `json:"max_surprisal_bits"`
	ThresholdBits float64 `json:"threshold_bits"`
	RecordID      string  `json:"record_id"`
	Note          string  `json:"note,omitempty"`
	flags         []replica.Flag
}

func (a *Auditor) seqParams() (float64, int, int) {
	thr, hist, min := a.P.SeqThresholdBits, a.P.SeqHistory, a.P.SeqMinHistory
	if thr <= 0 {
		thr = 12
	}
	if hist <= 0 {
		hist = 20000
	}
	if min <= 0 {
		min = 1000
	}
	return thr, hist, min
}

// token is what an event is to the sequence model: its action, the
// capability of an app event, and whether it failed.
func token(e replica.Entry) string {
	t := e.Event.Action
	if c, ok := e.Event.Detail["capability"].(string); ok && c != "" {
		t += ":" + c
	}
	if failure(e.Event.Result) {
		t += ":fail"
	}
	return t
}

// review is the value an Approver's range is set against: the forest's
// score, or for a sequence finding 0.5 at the threshold rising to 1 at
// twice the threshold.
func review(f replica.Flag, p Params) float64 {
	v := f.Score
	if f.Surprisal > 0 {
		thr := p.SeqThresholdBits
		if thr <= 0 {
			thr = 12
		}
		v = math.Max(v, 0.5+0.5*math.Min(1, (f.Surprisal-thr)/thr))
	}
	return v
}

// SequenceInfo is GET /v1/sequence: the model and its settings.
func (a *Auditor) SequenceInfo() map[string]any {
	thr, hist, min := a.seqParams()
	return map[string]any{"model": SeqModelName, "order": 3, "token": "action[:capability][:fail]", "threshold_bits": thr,
		"history_events": hist, "min_history_events": min, "model_sha256": a.seqModelHash(), "scored_through": a.Store.Meta("scored")}
}

func (a *Auditor) seqModelHash() string {
	thr, hist, min := a.seqParams()
	h := sha256.Sum256([]byte(fmt.Sprintf("%s/1 order=3 threshold_bits=%g history=%d min_history=%d token=action:capability[:fail]", SeqModelName, thr, hist, min)))
	return hex.EncodeToString(h[:])
}

// sequence scores the window's events [from, to] (window holds them, and
// maybe earlier ones) against a model of the history before from.
func (a *Auditor) sequence(ctx context.Context, window []replica.Entry, from, to uint64) (*SeqScan, error) {
	if to < from {
		return nil, nil // nothing new
	}
	thr, hist, min := a.seqParams()
	ss := &SeqScan{ThresholdBits: thr}
	hFrom := uint64(1)
	if from > uint64(hist) {
		hFrom = from - uint64(hist)
	}
	var past []replica.Entry
	if from > hFrom {
		var err error
		if past, err = a.Store.Events(hFrom, int(from-hFrom), "", ""); err != nil {
			return nil, err
		}
	}
	ss.History = len(past)
	byActor := map[string][]string{}
	var order []string
	for _, e := range past {
		if _, ok := byActor[e.Event.Actor]; !ok {
			order = append(order, e.Event.Actor)
		}
		byActor[e.Event.Actor] = append(byActor[e.Event.Actor], token(e))
	}
	streams := make([][]string, 0, len(order))
	for _, k := range order {
		streams = append(streams, byActor[k])
	}
	m := seqmodel.Fit(streams)
	ss.Vocabulary = m.Vocabulary()
	// each actor's last two events before the window
	last := map[string][2]string{}
	for k, s := range byActor {
		u, v := seqmodel.Start, seqmodel.Start
		if len(s) >= 1 {
			v = s[len(s)-1]
		}
		if len(s) >= 2 {
			u = s[len(s)-2]
		}
		last[k] = [2]string{u, v}
	}
	decision := ""
	if len(past) < min {
		ss.Note = fmt.Sprintf("not scored: %d events of history, the model needs %d", len(past), min)
		decision = ss.Note
	} else {
		for _, e := range window {
			if e.Seq < from {
				continue
			}
			w := token(e)
			c, ok := last[e.Event.Actor]
			if !ok {
				c = [2]string{seqmodel.Start, seqmodel.Start}
			}
			bits := m.Surprisal(c[0], c[1], w)
			ss.Scored++
			ss.MaxBits = math.Max(ss.MaxBits, bits)
			if bits >= thr {
				ss.flags = append(ss.flags, replica.Flag{Seq: e.Seq, Action: e.Event.Action, Actor: e.Event.Actor, Kind: "sequence",
					Surprisal: math.Round(bits*100) / 100, Expected: m.Likely(c[0], c[1], 3),
					Features: map[string]float64{"surprisal_bits": math.Round(bits*100) / 100}, At: time.Now().UTC()})
			}
			last[e.Event.Actor] = [2]string{c[1], w}
		}
		ss.Flagged = len(ss.flags)
		decision = fmt.Sprintf("flagged %d of %d events in %d-%d", ss.Flagged, ss.Scored, from, to)
	}
	in := []byte(fmt.Sprintf("seq %d-%d history %d", from, to, len(past)))
	for _, e := range window {
		if e.Seq >= from {
			in = append(in, e.Hash...)
		}
	}
	conf := 1.0
	if ss.MaxBits > 0 {
		conf = math.Max(0, 1-ss.MaxBits/(2*thr))
	}
	rid, err := a.Core.Reason(ctx, heain.Decision{Capability: "audit.sequence", Input: in, InputDataClass: "audit_replica",
		InputRef: fmt.Sprintf("audit-chain/%s/%d-%d", a.P.Node, from, to), Decision: decision,
		Value:     map[string]any{"flagged": ss.Flagged, "scored": ss.Scored, "max_surprisal_bits": math.Round(ss.MaxBits*100) / 100, "history_events": ss.History},
		Threshold: &heain.Threshold{Name: "surprisal_bits", Value: thr, Source: "app"}, Confidence: &conf,
		Summary: "Trigram model (Witten-Bell) of each actor's event stream, learned from the history before the window; events at or above the surprisal threshold are flagged for an Approver (advisory).",
		Factors: []heain.Factor{{Name: "history_events", Value: ss.History}, {Name: "vocabulary", Value: ss.Vocabulary},
			{Name: "events_scored", Value: ss.Scored}, {Name: "flagged", Value: ss.Flagged}},
		Role: "advisory", ModelSHA256: a.seqModelHash(), Runtime: "heain-audit sequence model (go)"})
	if err != nil {
		return nil, fmt.Errorf("sequence reasoning record: %w", err)
	}
	ss.RecordID = rid
	return ss, nil
}

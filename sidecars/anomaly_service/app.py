"""heain-audit anomaly-detection sidecar.

Scores a batch of audit events for anomalous patterns using scikit-learn's
IsolationForest -- an unsupervised model well suited to this task since
there is no labeled "this sequence was an attack" dataset to train a
supervised classifier on, and the goal is "flag what looks unusual
relative to the rest of this batch", which is exactly what an isolation
forest does.

Features per event (see build_features below):
  - inter_event_seconds: time since the previous event in the batch
    (0.0 for the first event in the batch). Flags bursts of activity or
    oddly long gaps.
  - action_frequency: how often this exact action string appears in the
    batch, as a fraction. A rare action (e.g. a single "delete_all" among
    a thousand "read" events) scores as more unusual.
  - actor_frequency: same idea, for the actor.
  - hour_of_day: the event's hour (0-23), as a float. Lets the model learn
    that most activity clusters in certain hours, so a 3am event among a
    batch of 9am-5pm events can stand out.

This is intentionally a simple, explainable feature set for Stage A, not
a sequence model (e.g. an LSTM/transformer over raw event text) -- see the
project's design notes for why: a hand-engineered feature set over a
small per-call batch is enough to demonstrate genuine anomaly scoring
without needing a training corpus that does not exist yet, while a
real sequence model is a natural Stage B upgrade once production audit
logs accumulate.

The /score endpoint never raises on "this batch looks totally normal" --
it returns an empty flags list. It can fail (e.g. too few events to fit a
meaningful model) and returns {"error": "..."} with HTTP 200 in that case
(not blocking heain-audit's own availability), or HTTP 500 for a genuine
unexpected failure.
"""
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from sklearn.ensemble import IsolationForest
import numpy as np

app = Flask(__name__)

# Below this many events in a batch, IsolationForest has too little data
# to produce a meaningful contamination estimate -- we simply report no
# flags rather than force a model fit that would just be noise.
MIN_EVENTS_FOR_SCORING = 5

# The fraction of a batch IsolationForest is told to expect as outliers.
# This is a model hyperparameter, not a claim that exactly this fraction
# of real audit batches are attacks -- it just bounds how many flags a
# single scoring pass can produce.
CONTAMINATION = 0.1

# A raw IsolationForest decision_function score below this is reported as
# a flag. More negative = more anomalous; this threshold was chosen so a
# clearly isolated point (e.g. a lone 3am event among daytime activity)
# flags, while borderline points do not -- see test_app.py for the
# concrete cases this was tuned against.
FLAG_SCORE_THRESHOLD = -0.05


def parse_timestamp(ts: str) -> datetime:
    # Events arrive as RFC3339Nano UTC strings from the Go side.
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def build_features(events: list[dict]) -> np.ndarray:
    n = len(events)
    actions = [e["action"] for e in events]
    actors = [e["actor"] for e in events]
    timestamps = [parse_timestamp(e["timestamp"]) for e in events]

    action_counts: dict[str, int] = {}
    actor_counts: dict[str, int] = {}
    for a in actions:
        action_counts[a] = action_counts.get(a, 0) + 1
    for a in actors:
        actor_counts[a] = actor_counts.get(a, 0) + 1

    # inter_event_seconds is undefined for the very first event in the
    # batch (there is no predecessor). Using 0.0 there would make the
    # first event look like a rapid-fire burst purely as an artifact of
    # batch boundaries, not real behavior -- so it is instead given the
    # median of the batch's own real gaps, which is a neutral "typical"
    # value and never itself the thing that makes an event stand out.
    raw_gaps = [
        (timestamps[i] - timestamps[i - 1]).total_seconds() for i in range(1, n)
    ]
    first_event_gap = float(np.median(raw_gaps)) if raw_gaps else 0.0

    features = np.zeros((n, 4), dtype=float)
    for i in range(n):
        inter_event = first_event_gap if i == 0 else raw_gaps[i - 1]
        features[i, 0] = inter_event
        features[i, 1] = action_counts[actions[i]] / n
        features[i, 2] = actor_counts[actors[i]] / n
        features[i, 3] = timestamps[i].astimezone(timezone.utc).hour
    return features


@app.route("/score", methods=["POST"])
def score():
    body = request.get_json(force=True)
    events = body.get("events", [])

    if len(events) < MIN_EVENTS_FOR_SCORING:
        return jsonify({"flags": []})

    try:
        features = build_features(events)
        model = IsolationForest(contamination=CONTAMINATION, random_state=0)
        model.fit(features)
        scores = model.decision_function(features)
    except Exception as exc:  # noqa: BLE001 -- report, never crash the sidecar
        return jsonify({"error": f"scoring failed: {exc}"}), 500

    flags = []
    for event, s in zip(events, scores):
        if s < FLAG_SCORE_THRESHOLD:
            flags.append(
                {
                    "sequence": event["sequence"],
                    "score": float(-s),  # report as a positive "how anomalous" score
                    "reason": "isolation-forest flagged this event's timing/frequency pattern as unusual relative to its batch",
                }
            )
    return jsonify({"flags": flags})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9810)

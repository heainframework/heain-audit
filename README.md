# heain-audit

The independent auditor base app of the heain framework. Universal infrastructure, like heain-job, heain-database and heain-access.

**v2 (Step 4c-2, 2026-10-06)** is rebuilt on heain-sdk v1 and heain-core 1.3. The Stage A version (its own plain-HTTP ledger, RSA-PSS key file, Python scikit-learn sidecar) is kept as tag `legacy-v0`.

## Role

heain-core keeps the node's formal audit chain itself: every app's formal events, AI reasoning records, P5 decisions and core's own events, durable, encrypted at rest and hash-chained (`hash = SHA-256(prev_hash ‖ seq ‖ ciphertext)`). heain-audit does **not** replace that log; it **watches it independently** (author decision 2026-10-06):

- **Reads** the chain through `GET /v1/app/audit/records` — only after an admin lists `heain-audit` in the node's `audit.readers` policy (Config API, through P5). Core audits the reading.
- **Verifies every link itself** (`heain.VerifyAuditRecords`) and keeps a **replica**: core's ciphertext and hashes as they were, plus the events sealed under heain-audit's data key from core's KMS.
- **Signs Merkle checkpoints** over ranges of the chain with its app key (`POST /v1/checkpoints`, automatic every `-checkpoint-every` records), and verifies them later against the replica, the signature and core (`GET /v1/checkpoints/{id}/verify`).
- **Detects divergence:** if core's chain no longer holds what the replica holds — truncated, replaced, or recomputed after a rewrite — heain-audit raises P5 `audit.divergence`, stops pulling and keeps the replica as evidence. A wiped and restarted chain verifies on its own; only an independent copy shows what was lost.
- **Reviews anomalies** with an Isolation Forest written in Go (no Python sidecar): features are the gap since the previous event, how rare the action and the actor are, the hour, and whether the result is a failure. Each scan sends a signed AI reasoning record; flagged events go to an Approver as one P5 `audit.anomaly_review` (`THRESHOLD_BASED`, value = the highest score, so an admin can set a range that is acknowledged automatically). heain-audit never acts on a finding itself.

## Endpoints

```
GET  /v1/status                        reader_allowed, core/replica head, scored_through, diverged, counts
GET  /v1/records?from=&limit=&actor=&action=     the replica (decrypted for the caller)
POST /v1/checkpoints   GET /v1/checkpoints   GET /v1/checkpoints/{id}/verify
POST /v1/anomaly/scan  GET /v1/anomalies     GET /v1/alerts
```

All are mTLS with app certificates (heain-sdk server); every formal call is audited in core. The replica is `sovereignty: node-local` and encrypted at rest.

## Running it

Any way you like — a plain process, a service unit, a container — configured through the heain-sdk `HEAIN_*` variables, plus `-pull-every` (5 s), `-checkpoint-every` (1000), `-scan-every` (500), `-threshold` (0.62), `-trees` (100), `-sample` (256), `-context` (500), and `HEAIN_LISTEN` (`:19470`). Then, once, on the node: `POST /v1/admin/config/policy/audit.readers {"value": ["heain-audit"]}` and an Approver approves.

Tests: `go test ./...`; live `bash scripts/live_4c.sh` (needs `~/heain-core`, `~/heain-sdk`); conformance `heain-conformance run --app .`.

**Not yet:** anchoring checkpoint roots outside the deployment (a notary or public ledger); reading the chains of other nodes (one heain-audit per node today); a sequence model for anomalies once real audit history exists.

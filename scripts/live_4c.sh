#!/usr/bin/env bash
# heain-audit live test 4c: heain-audit v2 on heain-sdk v1 as the independent auditor of a real
# heain-core node.
#  - it may read the node's audit chain only once an admin has listed it in audit.readers (P5);
#  - it verifies every link itself and keeps a sealed replica that matches core's chain;
#  - a signed Merkle checkpoint verifies (root, signature, core);
#  - an anomaly scan (Isolation Forest, signed reasoning record) flags rare failures and asks an
#    Approver through P5 (advisory);
#  - Stage B-3a: the sequence model (a trigram model of each actor's stream, learned from the history
#    before the window) files its own signed reasoning record with each scan, and scores once it has
#    enough history (here -sequence-min-history 100);
#  - when core's chain is replaced (an operator wipes audit.db), heain-audit detects the
#    divergence, keeps its replica as evidence and raises P5.
# The app is a plain process configured through HEAIN_* variables.
# Needs ~/heain-core and ~/heain-sdk. ~2 min.  Run from ~/heain-audit:  bash scripts/live_4c.sh
set -uo pipefail
AU=$(cd "$(dirname "$0")/.." && pwd)
cd ~/heain-core || { echo "needs ~/heain-core"; exit 1; }
H=./test_1_2_live.sh
T=$HOME/heain-core/.test-1.2
C=$T/certs; L=$T/logs; P=$T/pids; BIN=$T/node; W=$T/audit-4c
URL=https://127.0.0.1:18000
AURL=https://127.0.0.1:19470
PASS=0; FAIL=0
ok()  { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
as() { local who=$1; shift; curl -sk --noproxy '*' --cert "$C/$who.pem" --key "$C/$who.key" --cacert "$C/ca.pem" "$@"; }
code() { local who=$1; shift; as "$who" -o /dev/null -w "%{http_code}" "$@"; }
ld() { curl -sk --noproxy '*' --cert "$W/load.pem" --key "$W/load.key" --cacert "$C/ca.pem" "$@"; }   # app load-app.l1
au() { ld "$@"; }    # any app certificate may call heain-audit
j() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
mkcert() { [ -f "$C/$1.pem" ] && return; openssl genrsa -out "$C/$1.key" 2048 >/dev/null 2>&1
  openssl req -new -key "$C/$1.key" -subj "/CN=$1" -out "$C/$1.csr" >/dev/null 2>&1
  openssl x509 -req -in "$C/$1.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$C/$1.pem" \
    -days 825 -sha256 -extfile <(printf "subjectAltName=DNS:%s" "$1") >/dev/null 2>&1; }
startG() { nohup "$BIN" -node-id=G -tier=ZONE -raft-addr=127.0.0.1:19000 -data-dir="$T/data-G" -http-addr=127.0.0.1:18000 \
  -cert="$C/G.pem" -key="$C/G.key" -ca="$C/ca.pem" -admin-node-id=admin -approver-ids=approver-1 -bootstrap=true \
  -approval-store-path="$T/data-G/approvals.db" -provision-ca-cert="$W/prov.pem" -provision-ca-key="$W/prov.key" >> "$L/G.log" 2>&1 &
  echo $! > "$P/G.pid"; }
run_au() { mkdir -p "$W/state-a1"
  HEAIN_MANIFEST=$AU/heain-app.yaml HEAIN_INSTANCE=a1 HEAIN_CORE_URL=$URL HEAIN_CORE_ID=G HEAIN_CA=$C/ca.pem HEAIN_CHAIN=$W/prov.pem \
  HEAIN_STATE_DIR=$W/state-a1 HEAIN_ENROLL_TOKEN=$W/a1.tok HEAIN_ENDPOINT_BASE=$AURL HEAIN_LISTEN=127.0.0.1:19470 \
    nohup "$W/heain-audit" -pull-every 2s -checkpoint-every 0 -scan-every 0 -sequence-min-history 100 >> "$W/a1.log" 2>&1 &
  echo $! > "$P/a1.pid"; }
pending() { as approver-1 $URL/v1/admin/policy/pending | j "' '.join(x['ID'] for x in d['actions'] if x['Type']=='$1')"; }
until_ok() { for i in $(seq 1 ${2:-20}); do eval "$1" && return 0; sleep 1; done; return 1; }
st() { au $AURL/v1/status | j "$1"; }
coreaudit() { as admin "$URL/v1/admin/audit?from=${1:-1}&limit=1000"; }

echo "== 0. core node G, build heain-audit"
$H clean >/dev/null; $H build >/dev/null || { echo "core build failed"; exit 1; }; $H certs >/dev/null
mkdir -p "$L" "$P" "$T/data-G" "$W"; for c in admin approver-1; do mkcert $c; done
openssl genrsa -out "$W/prov.key" 2048 >/dev/null 2>&1
openssl req -new -key "$W/prov.key" -subj "/CN=heain-test-provisioning-ca" -out "$W/prov.csr" >/dev/null 2>&1
openssl x509 -req -in "$W/prov.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$W/prov.pem" -days 30 -sha256 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign") >/dev/null 2>&1
: > "$L/G.log"; startG; sleep 6
( cd "$AU" && GOFLAGS= GOWORK=${SDK_GOWORK:-} go build -o "$W/heain-audit" ./cmd/heain-audit ) && ok "heain-audit builds" || { bad "build"; exit 1; }
for k in $(seq 1 15); do [ "$(code admin -X POST -H 'Content-Type: application/json' -d '{"label":"probe.x"}' $URL/provision/token)" = 200 ] && break; sleep 1; done
# load-app.l1: an ordinary app whose formal events are the traffic heain-audit watches
as admin -X POST -H 'Content-Type: application/json' -d '{"label":"load-app.l1"}' $URL/provision/token > "$W/l1.json"
python3 - "$W" <<'PY'
import json,sys; w=sys.argv[1]; d=json.load(open(w+"/l1.json"))
open(w+"/l1.boot.pem","w").write(d["bootstrap_cert_pem"]+open(w+"/prov.pem").read()); open(w+"/l1.boot.key","w").write(d["bootstrap_key_pem"]); open(w+"/l1.token","w").write(d["token"])
PY
openssl genrsa -out "$W/load.key" 2048 >/dev/null 2>&1; openssl req -new -key "$W/load.key" -subj "/CN=load-app.l1" -out "$W/load.csr" >/dev/null 2>&1
python3 -c "import json;print(json.dumps({'token':open('$W/l1.token').read(),'csr_pem':open('$W/load.csr').read()}))" > "$W/l1.req"
curl -sk --noproxy '*' --cert "$W/l1.boot.pem" --key "$W/l1.boot.key" --cacert "$C/ca.pem" -X POST -H 'Content-Type: application/json' -d @"$W/l1.req" $URL/provision/csr \
  | python3 -c "import json,sys;open('$W/load.pem','w').write(json.load(sys.stdin)['cert_pem']+open('$W/prov.pem').read())"
ML='{"manifest_version":1,"app":{"id":"load-app","version":"1.0.0","group":"domain","api":"v1","sdk":{"name":"heain-sdk-go","version":">=1.0.0"}},"capabilities":[{"name":"load.work","version":1,"formal":true,"execution":"direct","ai":{"used":false}}],"endpoints":[{"method":"POST","path":"/v1/work","capability":"load.work","formal":true}]}'
id=$(ld -X POST -d "{\"manifest\":$ML,\"instance_id\":\"l1\"}" $URL/v1/app/register | j "d.get('action_id','')"); [ -n "$id" ] && code approver-1 -X POST $URL/v1/admin/policy/$id/approve >/dev/null
event() { ld -o /dev/null -X POST -d "{\"trace_id\":\"t-$RANDOM$RANDOM\",\"capability\":\"load.work\",\"actor\":\"client.$1\",\"outcome\":\"$2\",\"at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"detail\":{\"note\":\"load-secret-marker\"}}" $URL/v1/app/audit/events; }

echo "== 1. heain-audit starts; it may read core's chain only when an admin lists it"
as admin -X POST -H 'Content-Type: application/json' -d '{"label":"heain-audit.a1"}' $URL/provision/token > "$W/a1.tok"
run_au
until_ok '[ -n "$(pending app.register)" ]' 30; for a in $(pending app.register); do code approver-1 -X POST $URL/v1/admin/policy/$a/approve >/dev/null; done
until_ok 'grep -q "heain-audit: active" "$W/a1.log"' 30 && ok "heain-audit a1 admitted (P5 app.register) and serving" || { bad "start: $(tail -3 "$W/a1.log")"; $H stop-all >/dev/null 2>&1; exit 1; }
sleep 3
[ "$(st "d['reader_allowed']")" = False ] && [ "$(st "d['replica_head']")" = 0 ] && ok "not in audit.readers yet: core refuses, replica empty" || bad "reader before policy: $(au $AURL/v1/status)"
AID=$(as admin -X POST -d '{"value":["heain-audit"]}' $URL/v1/admin/config/policy/audit.readers | j "d['action_id']")
[ -n "$AID" ] && code approver-1 -X POST $URL/v1/admin/policy/$AID/approve >/dev/null
until_ok '[ "$(st "d[\"reader_allowed\"]")" = True ] && [ "$(st "d[\"replica_head\"]")" -gt 0 ]' && ok "admin set audit.readers=[heain-audit] through P5; heain-audit reads the chain" || bad "reader: $(au $AURL/v1/status)"

echo "== 2. an independent, verified replica"
for i in $(seq 1 240); do event $((i % 4)) ok; done
for i in 1 2 3; do event intruder "error:denied"; sleep 1; done
for i in $(seq 1 20); do event $((i % 4)) ok; done
HEAD=$(as admin $URL/v1/admin/audit/verify | j "d['records']")
until_ok '[ "$(st "d[\"replica_head\"]")" -ge '"$HEAD"' ]' 20 && ok "replica caught up with core ($(st "d['replica_head']") records, every link verified by heain-audit)" || bad "catch-up: $(au $AURL/v1/status)"
python3 - "$(coreaudit 100 | j "json.dumps({str(r['seq']):r['hash'] for r in d['records']})")" "$(au "$AURL/v1/records?from=100&limit=1000" | j "json.dumps({str(r['seq']):r['hash'] for r in d['records']})")" <<'PY' && ok "replica hashes equal core's chain hashes" || bad "hash mismatch"
import json,sys
a,b=json.loads(sys.argv[1]),json.loads(sys.argv[2])
sys.exit(0 if a and all(b.get(k)==v for k,v in a.items() if k in b) and len(set(a)&set(b))>=100 else 1)
PY
[ "$(au "$AURL/v1/records?action=app.audit_read&limit=1000" | j "len(d['records'])")" -ge 1 ] && ok "core audited heain-audit's reading (app.audit_read)" || bad "read audit"
[ "$(coreaudit | j "sum(1 for r in d['records'] if r['event']['Action']=='app.audit_read')")" -le 2 ] && ok "reads are audited sparingly (polling does not feed the chain it reads)" || bad "read audit flood"
! grep -rqaF load-secret-marker "$W/state-a1" && ok "the replica holds no plaintext event detail (sealed under its data key from core)" || bad "plaintext in replica"

echo "== 3. signed Merkle checkpoint"
r=$(au -X POST $AURL/v1/checkpoints -w '\n%{http_code}'); CP=$(echo "$r" | head -1 | j "d['id']")
[ "$(echo "$r" | tail -1)" = 201 ] && [ "$(echo "$r" | head -1 | j "d['from']")" = 1 ] && ok "checkpoint $CP over 1-$(echo "$r" | head -1 | j "d['to']") (root signed with heain-audit's app key)" || bad "checkpoint: $r"
[ "$(au $AURL/v1/checkpoints/$CP/verify | j "str(d['root_ok'])+str(d['signature_ok'])+str(d['core_ok'])")" = TrueTrueTrue ] && ok "verify: root, signature and core's chain all match" || bad "verify: $(au $AURL/v1/checkpoints/$CP/verify)"
[ "$(au -o /dev/null -w '%{http_code}' -X POST $AURL/v1/checkpoints)" = 409 ] || [ "$(st "d['replica_head']")" -gt "$(au $AURL/v1/checkpoints | j "d['checkpoints'][-1]['to']")" ] && ok "nothing new -> 409 (or new records arrived meanwhile)" || bad "409"

echo "== 4. anomaly review (Isolation Forest, advisory through P5)"
r=$(au -X POST -d '{}' $AURL/v1/anomaly/scan)
IN=$(coreaudit | j "' '.join(str(r['seq']) for r in d['records'] if r['event']['Action']=='app.event' and r['event']['Result']=='error:denied')")
FL=$(echo "$r" | j "' '.join(str(f['seq']) for f in (d['flagged'] or []))")
python3 -c "import sys;i=set('$IN'.split());f=set('$FL'.split());sys.exit(0 if len(i)==3 and i<=f and len(f)*10<=int('$(echo "$r" | j "d['scored']")') else 1)" && ok "the 3 denied events are flagged, at most 10% of events ($(echo $FL | wc -w) flagged of $(echo "$r" | j "d['scored']") scored, max score $(echo "$r" | j "d['max_score']"))" || bad "flags: denied=[$IN] flagged=[$FL]"
RID=$(echo "$r" | j "d['record_id']"); ACT=$(echo "$r" | j "d.get('action_id','')")
[ "$(coreaudit | j "sum(1 for r in d['records'] if r['event']['Action']=='ai.reasoning_record' and r['event']['Detail']['record']['record_id']=='$RID')")" = 1 ] && ok "a signed reasoning record of the scan is in core's audit" || bad "record"
[ -n "$ACT" ] && [ "$(as approver-1 $URL/v1/admin/policy/pending | j "[a['Type'] for a in d['actions'] if a['ID']=='$ACT'][0]")" = audit.anomaly_review ] && ok "the Approver is asked to review (P5 audit.anomaly_review); heain-audit acts on nothing itself" || bad "P5 review: $ACT"
[ "$(au $AURL/v1/anomalies | j "len(d['flags'])")" = "$(echo $FL | wc -w)" ] && ok "flags kept with their record and action" || bad "flags list"
SR=$(echo "$r" | j "d['sequence']['record_id']")
[ -n "$SR" ] && [ "$(echo "$r" | j "d['sequence']['scored']")" = 0 ] && [ "$(coreaudit | j "sum(1 for r in d['records'] if r['event']['Action']=='ai.reasoning_record' and r['event']['Detail']['record']['record_id']=='$SR' and r['event']['Detail']['record']['model']['name']=='trigram-witten-bell')")" = 1 ] \
  && ok "the sequence model filed its own record (trigram-witten-bell): $(echo "$r" | j "d['sequence']['note']")" || bad "sequence record: $(echo "$r" | j "d.get('sequence')")"

echo "== 4b. the sequence model, once it has history (B-3a)"
for i in $(seq 1 40); do event $((i % 4)) ok; done
HEAD=$(as admin $URL/v1/admin/audit/verify | j "d['records']")
until_ok '[ "$(st "d[\"replica_head\"]")" -ge '"$HEAD"' ]' 20
r=$(au -X POST -d '{}' $AURL/v1/sequence/scan)
SQ=$(echo "$r" | j "d['sequence']")
[ "$(echo "$r" | j "d['sequence']['history_events'] >= 100 and d['sequence']['scored'] == d['scored'] and d['sequence']['vocabulary'] > 1")" = True ] \
  && ok "scored $(echo "$r" | j "d['sequence']['scored']") new events against $(echo "$r" | j "d['sequence']['history_events']") of history ($(echo "$r" | j "d['sequence']['vocabulary']") kinds of event), max surprisal $(echo "$r" | j "d['sequence']['max_surprisal_bits']") bits, $(echo "$r" | j "d['sequence']['flagged']") flagged at $(echo "$r" | j "d['sequence']['threshold_bits']") bits" || bad "sequence scan: $SQ"
SR=$(echo "$r" | j "d['sequence']['record_id']")
RH=$(coreaudit "$HEAD" | j "[r['event']['Detail']['record']['model'].get('artifact_sha256') for r in d['records'] if r['event']['Action']=='ai.reasoning_record' and r['event']['Detail']['record']['record_id']=='$SR'][0]")
GH=$(au $AURL/v1/sequence | j "d['model_sha256']")
[ -n "$RH" ] && [ "$RH" = "$GH" ] \
  && ok "its record names the model by the hash GET /v1/sequence reports" || bad "sequence model hash: record [$RH] /v1/sequence [$GH] $(au $AURL/v1/sequence | head -c 300)"

echo "== 5. core's chain replaced: divergence detected, replica kept as evidence"
RH=$(st "d['replica_head']")
kill -TERM "$(cat "$P/G.pid")"; sleep 3; mkdir -p "$W/wiped"; mv "$T/data-G/audit.db" "$W/wiped/"; startG; sleep 8
until_ok '[ "$(st "d[\"diverged\"]")" = True ]' 30 && ok "heain-audit detected that core's chain no longer holds its records" || bad "divergence: $(au $AURL/v1/status)"
[ "$(st "d['replica_head']")" = "$RH" ] && ok "the replica still holds all $RH records (evidence)" || bad "replica changed"
[ -n "$(pending audit.divergence)" ] && ok "P5 audit.divergence raised for the Approver" || bad "no divergence P5"
[ "$(au $AURL/v1/checkpoints/$CP/verify | j "str(d['root_ok'])+str(d['signature_ok'])+str(d['core_ok'])")" = TrueTrueFalse ] && ok "the checkpoint still verifies on the replica and its signature, not on core" || bad "verify after wipe: $(au $AURL/v1/checkpoints/$CP/verify)"
[ "$(as admin "$URL/v1/admin/audit/verify" | j "d['ok']")" = True ] && ok "core's new chain verifies on its own -- only the independent replica shows what was lost" || bad "core verify"

echo "== cleanup"
kill -TERM "$(cat "$P/a1.pid")" 2>/dev/null; sleep 2
$H stop-all >/dev/null 2>&1
echo
echo "RESULT: $PASS passed, $FAIL failed"

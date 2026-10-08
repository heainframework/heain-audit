#!/usr/bin/env bash
# heain-audit live test B-1d (Stage B, author decisions 2026-10-08): checkpoints go up to the zone
# Master's heain-audit, which witnesses them; checkpoints are anchored with an RFC 3161 time-stamp
# authority (a TEST ONLY TSA here: openssl ts -reply, tools/test-tsa).
#   G (18000, Master, farm registry) <- W (18003, farm Worker); heain-audit a1 on G (anchors), w1 on W.
#  - w1 sends its signed checkpoints (roots only) to a1; a1 refuses another app and a checkpoint signed
#    for another node;
#  - a1 anchors its own and W's checkpoints under one root the TSA stamps; the anchor verifies, and the
#    token verifies offline with openssl ts -verify;
#  - G down: w1 keeps its checkpoints and sends them when G is back;
#  - w1's replica reset, then a checkpoint over records it had already covered: a1 raises a conflict
#    (alert + P5 audit.divergence);
#  - none of W's events reach G.
# Needs ~/heain-core, ~/heain-sdk, openssl. ~3 min.  Run from ~/heain-audit:  bash scripts/live_b1d.sh
set -uo pipefail
AU=$(cd "$(dirname "$0")/.." && pwd)
cd ~/heain-core || { echo "needs ~/heain-core"; exit 1; }
H=./test_1_2_live.sh
T=$HOME/heain-core/.test-1.2
C=$T/certs; L=$T/logs; P=$T/pids; BIN=$T/node; W=$T/audit-b1d
URL=https://127.0.0.1:18000; WURL=https://127.0.0.1:18003
A1=https://127.0.0.1:19470; W1=https://127.0.0.1:19471
TSA=http://127.0.0.1:18480
PASS=0; FAIL=0
ok()  { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
as() { local who=$1; shift; curl -sk --noproxy '*' --cert "$C/$who.pem" --key "$C/$who.key" --cacert "$C/ca.pem" "$@"; }
code() { local who=$1; shift; as "$who" -o /dev/null -w "%{http_code}" "$@"; }
cl() { local who=$1; shift; curl -sk --noproxy '*' --cert "$W/$who.pem" --key "$W/$who.key" --cacert "$C/ca.pem" -H 'Content-Type: application/json' "$@"; }
j() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
mkcert() { [ -f "$C/$1.pem" ] && return; openssl genrsa -out "$C/$1.key" 2048 >/dev/null 2>&1
  openssl req -new -key "$C/$1.key" -subj "/CN=$1" -out "$C/$1.csr" >/dev/null 2>&1
  openssl x509 -req -in "$C/$1.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$C/$1.pem" \
    -days 825 -sha256 -extfile <(printf "subjectAltName=DNS:%s" "$1") >/dev/null 2>&1; }
until_ok() { for i in $(seq 1 ${2:-30}); do eval "$1" && return 0; sleep 1; done; return 1; }
runapp() { # <instance> <port> <core-url> <core-id> [args...]
  local inst=$1 port=$2 cu=$3 cid=$4; shift 4; mkdir -p "$W/state-$inst"
  env HEAIN_MANIFEST=$AU/heain-app.yaml HEAIN_INSTANCE=$inst HEAIN_CORE_URL=$cu HEAIN_CORE_ID=$cid HEAIN_CA=$C/ca.pem HEAIN_CHAIN=$W/prov.pem \
    HEAIN_ENROLL_CORE_URL=$URL HEAIN_ENROLL_CORE_ID=G HEAIN_STATE_DIR=$W/state-$inst HEAIN_ENROLL_TOKEN=$W/$inst.tok \
    HEAIN_ENDPOINT_BASE=https://127.0.0.1:$port HEAIN_LISTEN=127.0.0.1:$port \
    nohup "$W/heain-audit" -pull-every 1s -scan-every 0 "$@" >> "$W/$inst.log" 2>&1 &
  echo $! > "$P/app-$inst.pid"; }
token() { as admin -X POST -H 'Content-Type: application/json' -d "{\"label\":\"$1\"}" $URL/provision/token > "$W/$2.tok"; }
approve_all() { for u in $URL $WURL; do
    for a in $(as approver-1 $u/v1/admin/policy/pending | j "' '.join(x['ID'] for x in d['actions'] if x['Type']=='app.register')"); do
      code approver-1 -X POST $u/v1/admin/policy/$a/approve >/dev/null; done; done; }
active() { for i in $(seq 1 60); do approve_all; [ "$(grep -c "heain-audit: active" "$W/$1.log" 2>/dev/null)" -ge "${2:-1}" ] && return 0; sleep 1; done; return 1; }
setpol() { local id; id=$(as admin -X POST -d "{\"value\":$3}" $1/v1/admin/config/policy/$2 | j "d['action_id']"); [ -n "$id" ] && [ "$(code approver-1 -X POST $1/v1/admin/policy/$id/approve)" = 200 ]; }
client() { # <label>
  as admin -X POST -H 'Content-Type: application/json' -d "{\"label\":\"$1\"}" $URL/provision/token > "$W/$1.json"
  python3 - "$W" "$1" <<'PY'
import json,sys; w,l=sys.argv[1],sys.argv[2]; d=json.load(open(f"{w}/{l}.json"))
open(f"{w}/{l}.boot.pem","w").write(d["bootstrap_cert_pem"]+open(w+"/prov.pem").read()); open(f"{w}/{l}.boot.key","w").write(d["bootstrap_key_pem"]); open(f"{w}/{l}.token","w").write(d["token"])
PY
  openssl genrsa -out "$W/$1.key" 2048 >/dev/null 2>&1; openssl req -new -key "$W/$1.key" -subj "/CN=$1" -out "$W/$1.csr" >/dev/null 2>&1
  python3 -c "import json;print(json.dumps({'token':open('$W/$1.token').read(),'csr_pem':open('$W/$1.csr').read()}))" > "$W/$1.req"
  curl -sk --noproxy '*' --cert "$W/$1.boot.pem" --key "$W/$1.boot.key" --cacert "$C/ca.pem" -X POST -H 'Content-Type: application/json' -d @"$W/$1.req" $URL/provision/csr \
    | python3 -c "import json,sys;open('$W/$1.pem','w').write(json.load(sys.stdin)['cert_pem']+open('$W/prov.pem').read())"; }
witnessed() { local n; n=$(cl ops.c1 "$A1/v1/witness/checkpoints?node=W" | j "len(d['witnessed'])"); echo "${n:-0}"; }
cleanup() { for f in "$P"/app-*.pid "$P"/tsa.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; done; true; }
trap cleanup EXIT

echo "== 0. Master G + farm Worker W; build heain-audit and the TEST ONLY TSA"
$H clean >/dev/null; $H build >/dev/null || { echo "core build failed"; exit 1; }; $H certs >/dev/null
mkdir -p "$L" "$P" "$T/data-G" "$T/data-W" "$W"; for c in admin approver-1; do mkcert $c; done
openssl genrsa -out "$W/prov.key" 2048 >/dev/null 2>&1
openssl req -new -key "$W/prov.key" -subj "/CN=heain-test-provisioning-ca" -out "$W/prov.csr" >/dev/null 2>&1
openssl x509 -req -in "$W/prov.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$W/prov.pem" -days 30 -sha256 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign") >/dev/null 2>&1
: > "$L/G.log"; : > "$L/W.log"
startG() { nohup "$BIN" -node-id=G -tier=ZONE -raft-addr=127.0.0.1:19000 -data-dir="$T/data-G" -http-addr=127.0.0.1:18000 \
  -cert="$C/G.pem" -key="$C/G.key" -ca="$C/ca.pem" -admin-node-id=admin -approver-ids=approver-1 -bootstrap=true \
  -approval-store-path="$T/data-G/approvals.db" -farm-registry-ttl=30s -provision-ca-cert="$W/prov.pem" -provision-ca-key="$W/prov.key" >> "$L/G.log" 2>&1 &
  echo $! > "$P/G.pid"; }
startG; sleep 6
nohup "$BIN" -node-id=W -tier=WORKER -raft-addr=127.0.0.1:19003 -data-dir="$T/data-W" -http-addr=127.0.0.1:18003 \
  -cert="$C/W.pem" -key="$C/W.key" -ca="$C/ca.pem" -admin-node-id=admin -approver-ids=approver-1 -bootstrap=false \
  -approval-store-path="$T/data-W/approvals.db" \
  -farm-register-addr=https://127.0.0.1:18000 -farm-register-node-id=G -self-addr=https://127.0.0.1:18003 -farm-register-interval=2s >> "$L/W.log" 2>&1 &
echo $! > "$P/W.pid"; sleep 5
B="GOFLAGS= GOWORK=${SDK_GOWORK:-}"
( cd "$AU" && eval "$B go build -o $W/heain-audit ./cmd/heain-audit" && eval "$B go build -o $W/test-tsa ./tools/test-tsa" ) \
  && ok "heain-audit and the TEST ONLY TSA build" || { bad "build"; exit 1; }
nohup "$W/test-tsa" -listen 127.0.0.1:18480 -dir "$W/tsa" >> "$W/tsa.log" 2>&1 & echo $! > "$P/tsa.pid"
for k in $(seq 1 15); do [ "$(code admin -X POST -H 'Content-Type: application/json' -d '{"label":"probe.x"}' $URL/provision/token)" = 200 ] && break; sleep 1; done
client ops.c1; client heain-audit.x9
for u in $URL $WURL; do setpol $u audit.readers '["heain-audit"]' || bad "audit.readers on $u"; done

echo "== 1. a1 on G (anchors), w1 on W (checkpoint every 15 records)"
token heain-audit.a1 a1; token heain-audit.w1 w1
runapp a1 19470 $URL G -checkpoint-every 15 -tsa-url $TSA -tsa-ca "$W/tsa/ca.pem" -anchor-every 3s
runapp w1 19471 $WURL W -checkpoint-every 15
active a1 && active w1 && ok "a1 active on G, w1 active on W" || { bad "start: $(tail -3 "$W/a1.log") / $(tail -3 "$W/w1.log")"; exit 1; }
# make audit records on W (each config change is audited there) so w1 checkpoints; the marker is the reason
churn() { for i in $(seq 1 ${2:-20}); do code admin -X PUT -d "{\"value\":\"$((2 + i % 2))s\",\"reason\":\"W-ONLY-SECRET-$i\"}" $1/v1/admin/config/system/zone.sync_interval >/dev/null; done; }
churn $WURL 20
until_ok '[ "$(witnessed)" -ge 1 ] 2>/dev/null' 60 && ok "w1's checkpoint reached a1 on the zone Master ($(witnessed) witnessed)" || bad "no checkpoint witnessed: $(tail -3 "$W/w1.log")"
r=$(cl ops.c1 "$A1/v1/witness/checkpoints?node=W" | j "d['witnessed'][0]['from']")
[ "$r" = heain-audit.w1 ] && ok "sent by heain-audit.w1, signed with its certificate" || bad "sender: $r"

echo "== 2. who may send"
CP=$(cl ops.c1 "$A1/v1/witness/checkpoints?node=W" | python3 -c "import json,sys;print(json.dumps(json.load(sys.stdin)['witnessed'][0]['checkpoint']))")
c=$(cl ops.c1 -o /dev/null -w '%{http_code}' -X POST -d "{\"node\":\"W\",\"checkpoint\":$CP}" $A1/v1/witness/checkpoints)
[ "$c" = 403 ] && ok "another app cannot send checkpoints (403)" || bad "other app: $c"
c=$(cl heain-audit.x9 -o /dev/null -w '%{http_code}' -X POST -d "{\"node\":\"W\",\"checkpoint\":$CP}" $A1/v1/witness/checkpoints)
[ "$c" = 403 ] && ok "another heain-audit cannot pass off w1's checkpoint (not signed with its certificate)" || bad "replayed by x9: $c"

echo "== 3. anchoring (RFC 3161)"
until_ok '[ "$(cl ops.c1 $A1/v1/anchors | j "sum(1 for a in d[\"anchors\"] for l in a[\"leaves\"] if l[\"node\"]==\"W\")")" -ge 1 ]' 30 \
  && ok "a1 anchored a root covering its own and W's checkpoints" || bad "no anchor: $(tail -3 "$W/a1.log")"
AN=$(cl ops.c1 $A1/v1/anchors | j "[a['id'] for a in d['anchors'] if any(l['node']=='W' for l in a['leaves'])][0]")
v=$(cl ops.c1 $A1/v1/anchors/$AN/verify)
[ "$(echo "$v" | j "(d['root_ok'],d['token_ok'],d['tsa_sig_ok'],d['leaves_ok'])")" = "(True, True, True, True)" ] && ok "anchor $AN verifies: root, token, TSA signature, every leaf's checkpoint signature" || bad "verify: $v"
ROOT=$(cl ops.c1 $A1/v1/anchors | j "[a['root'] for a in d['anchors'] if a['id']=='$AN'][0]")
cl ops.c1 -o "$W/$AN.tsr" $A1/v1/anchors/$AN/token
openssl ts -verify -digest "$ROOT" -token_in -in "$W/$AN.tsr" -CAfile "$W/tsa/ca.pem" 2>&1 | grep -q "Verification: OK" \
  && ok "the token verifies offline with openssl ts -verify" || bad "openssl verify"
other=$(printf x | sha256sum | cut -c1-64)
! openssl ts -verify -digest "$other" -token_in -in "$W/$AN.tsr" -CAfile "$W/tsa/ca.pem" 2>&1 | grep -q "Verification: OK" && ok "and not for another root" || bad "token verified another root"

echo "== 4. G down: w1 keeps its checkpoints and sends them later"
wcps() { as admin "$WURL/v1/admin/audit?limit=20000" | j "sum(1 for x in d['records'] if x['event']['Action']=='app.event' and x['event']['Detail'].get('capability')=='audit.checkpoint')"; }
n0=$(witnessed); k0=$(wcps)
kill "$(cat "$P/app-a1.pid")"; kill "$(cat "$P/G.pid")"; sleep 12
churn $WURL 20
until_ok '[ "$(wcps)" -gt "$k0" ] 2>/dev/null' 40 && ok "w1 made a checkpoint while G was down (audited in W's core)" || bad "no checkpoint on W while G down"
startG; sleep 6
runapp a1 19470 $URL G -checkpoint-every 15 -tsa-url $TSA -tsa-ca "$W/tsa/ca.pem" -anchor-every 3s
active a1 2 >/dev/null
until_ok '[ "$(witnessed)" -gt "$n0" ] 2>/dev/null' 60 && ok "G back: a1 has the checkpoints w1 made meanwhile ($(witnessed) witnessed)" || bad "catch-up: $(tail -3 "$W/w1.log")"

echo "== 5. a checkpoint over records already covered is a conflict"
kill "$(cat "$P/app-w1.pid")"; sleep 2; rm -rf "$W/state-w1/replica.db"
runapp w1 19471 $WURL W -checkpoint-every 1000000
active w1 2 >/dev/null; sleep 4
c=$(cl ops.c1 -o /dev/null -w '%{http_code}' -X POST $W1/v1/checkpoints)
until_ok '[ "$(cl ops.c1 $A1/v1/alerts | j "len(d[\"alerts\"])")" -ge 1 ]' 30 \
  && ok "w1 (replica reset) checkpoints records it had covered: a1 raises a conflict" || bad "no conflict: $(tail -3 "$W/w1.log")"
[ "$(as approver-1 $URL/v1/admin/policy/pending | j "sum(1 for x in d['actions'] if x['Type']=='audit.divergence')")" -ge 1 ] \
  && ok "and asks an Approver (P5 audit.divergence)" || bad "no P5 item"

echo "== 6. roots only"
! grep -rqaF "W-ONLY-SECRET" "$W/state-a1" && ok "none of W's events reached a1 (only signed roots)" || bad "W's events on G"
[ "$(as admin "$URL/v1/admin/audit?limit=20000" | j "sum(1 for x in d['records'] if x['event']['Action']=='app.event' and x['event']['Detail'].get('capability')=='audit.witness')")" -ge 1 ] \
  && ok "receiving is audited in G's core (audit.witness)" || bad "witness audit"

echo "== cleanup"
cleanup; $H stop-all >/dev/null 2>&1
echo
echo "RESULT: $PASS passed, $FAIL failed"
echo "(logs: $W)"

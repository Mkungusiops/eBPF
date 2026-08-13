#!/usr/bin/env bash
# netns-smoke.sh — Stage-0 end-to-end smoke test for the network choke.
#
# Stands up the 3-netns lab, runs the engine in ns-gw with the real tc data
# plane attached to the LAN-side veth, flips the device gateway to enforcing,
# then asserts that:
#   1. the data plane actually attached (links_attached > 0),
#   2. a device reaches upstream at baseline,
#   3. after `sever`, that device's forwarded traffic is DROPPED,
#   4. the device shows state=severed via the API,
#   5. after `thaw`, traffic is RESTORED.
#
# Linux + root only. Exits non-zero on any failed assertion so it works as a
# CI/dev gate. Usage (normally via `make netns-smoke`):
#   sudo bash scripts/dev/netns-smoke.sh /path/to/devchoke.o /path/to/engine-bin
set -uo pipefail

OBJ="${1:?usage: netns-smoke.sh DEVCHOKE_OBJ ENGINE_BIN}"
BIN="${2:?usage: netns-smoke.sh DEVCHOKE_OBJ ENGINE_BIN}"
LAB="$(cd "$(dirname "$0")" && pwd)/netns-lab.sh"
GW_LAN=veth-gw-lan
URL="http://127.0.0.1:8080"

PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

[[ "$(uname -s)" == "Linux" ]] || { echo "Linux only"; exit 2; }
[[ "$(id -u)" == "0" ]]        || { echo "must run as root (try: sudo make netns-smoke)"; exit 2; }
[[ -f "$OBJ" ]] || { echo "missing $OBJ — run: make devchoke"; exit 2; }
[[ -x "$BIN" ]] || { echo "missing engine binary $BIN — run: make build-linux"; exit 2; }
command -v ip >/dev/null || { echo "iproute2 (ip) required"; exit 2; }

ENGINE_PID=""; JAR=""
cleanup() {
  [[ -n "$ENGINE_PID" ]] && kill "$ENGINE_PID" 2>/dev/null
  [[ -n "$JAR" ]] && rm -f "$JAR"
  bash "$LAB" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== lab up =="
bash "$LAB" up >/dev/null
DEV_MAC=$(ip -n ns-dev link show veth-dev | awk '/link\/ether/{print $2}')
echo "device MAC: $DEV_MAC"

echo "== starting engine in ns-gw (attach $GW_LAN) =="
ip netns exec ns-gw "$BIN" -fake -db /tmp/netns-smoke.db -http 127.0.0.1:8080 \
  -devchoke-obj "$OBJ" -devchoke-iface "$GW_LAN" >/tmp/netns-smoke-engine.log 2>&1 &
ENGINE_PID=$!

# Wait for the HTTP listener.
up=0
for _ in $(seq 1 40); do
  if ip netns exec ns-gw curl -s -o /dev/null "$URL/login" 2>/dev/null; then up=1; break; fi
  sleep 0.25
done
if [[ "$up" != "1" ]]; then
  echo "FAIL: engine did not come up; log:"; sed 's/^/    /' /tmp/netns-smoke-engine.log; exit 1
fi

# Login -> cookie jar; grab CSRF for POSTs.
JAR=$(mktemp)
ip netns exec ns-gw curl -s -c "$JAR" -d 'user=admin&pass=ebpf-soc-demo' "$URL/api/login" >/dev/null
CSRF=$(awk '$6=="csrf_token"{print $7}' "$JAR")

GET()  { ip netns exec ns-gw curl -s -b "$JAR" "$URL$1"; }
POST() { ip netns exec ns-gw curl -s -b "$JAR" -H "X-CSRF-Token: $CSRF" -H 'content-type: application/json' -X POST "$URL$1" -d "$2"; }
ping_ok() { ip netns exec ns-dev ping -c1 -W1 10.0.1.2 >/dev/null 2>&1; }

# Device choke intentionally boots detect-only; the destructive half of this
# smoke test must explicitly switch the lab gateway to enforcing.
POST /api/choke/device-mode '{"enforcing":true,"reason":"netns smoke"}' >/dev/null

echo "== assertions =="

STATE=$(GET /api/choke/device-state)
LINKS=$(printf '%s' "$STATE" | grep -o '"links_attached":[0-9]*' | grep -o '[0-9]*')
echo "  device-state: $STATE"
if [[ "${LINKS:-0}" -gt 0 ]]; then ok "data plane attached (links_attached=$LINKS)"; else
  bad "data plane attached (links_attached=${LINKS:-0}) — engine log:"; sed 's/^/    /' /tmp/netns-smoke-engine.log
fi

if ping_ok; then ok "baseline: device reaches upstream"; else bad "baseline: device reaches upstream"; fi

# After traffic has flowed, the data plane must have OBSERVED forwarded
# frames. frames_seen==0 here with links>0 is the bridge-master / wrong-iface
# mistake — the program attached but isn't in the traffic path.
FRAMES=$(GET /api/choke/device-state | grep -o '"frames_seen":[0-9]*' | grep -o '[0-9]*')
if [[ "${FRAMES:-0}" -gt 0 ]]; then ok "data plane sees forwarded frames (frames_seen=$FRAMES)"; else
  bad "data plane sees forwarded frames (frames_seen=${FRAMES:-0}) — attached to the wrong interface?"
fi

POST /api/choke/device-jail "{\"macs\":[\"$DEV_MAC\"],\"action\":\"sever\",\"reason\":\"smoke\"}" >/dev/null
sleep 0.5
if ping_ok; then bad "after sever: traffic should be DROPPED but still flows"; else ok "after sever: device traffic dropped"; fi

if GET /api/choke/devices | grep -q '"state":"severed"'; then ok "API reports device state=severed"; else bad "API reports device state=severed"; fi

POST /api/choke/device-thaw "{\"mac\":\"$DEV_MAC\",\"reason\":\"done\"}" >/dev/null
sleep 0.5
if ping_ok; then ok "after thaw: device traffic restored"; else bad "after thaw: device traffic restored"; fi

echo "== result: $PASS passed, $FAIL failed =="
[[ "$FAIL" -eq 0 ]]

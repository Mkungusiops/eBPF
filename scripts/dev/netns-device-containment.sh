#!/usr/bin/env bash
# netns-device-containment.sh — operator-style device containment demo.
#
# Builds on the 3-netns lab:
#   ns-dev  ->  ns-gw running the platform + TC device choke  ->  ns-net
#
# The "device" generates benign-looking and suspicious-looking network flows
# to an isolated upstream namespace. The script then uses the platform API to:
#   1. inspect device flows,
#   2. switch device mode to enforcing,
#   3. sever the device MAC,
#   4. verify traffic is blocked,
#   5. thaw the device and verify traffic returns.
#
# No payloads leave the lab; the suspicious process is only a traffic generator
# that connects to a high port (:4444) in ns-net.
set -uo pipefail

OBJ="${1:?usage: netns-device-containment.sh DEVCHOKE_OBJ ENGINE_BIN}"
BIN="${2:?usage: netns-device-containment.sh DEVCHOKE_OBJ ENGINE_BIN}"
LAB="$(cd "$(dirname "$0")" && pwd)/netns-lab.sh"
GW_LAN=veth-gw-lan
URL="http://127.0.0.1:8080"
# Must satisfy the engine's password policy (14+ chars, upper, 3 digits, 3
# specials) or it refuses to start. The lab is loopback-only inside a netns.
LAB_PASS='Lab#Choke$Demo7!42'

PASS=0
FAIL=0
ENGINE_PID=""
SERVER_PID=""
GEN_PID=""
PING_PID=""
JAR=""

ok() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

cleanup() {
  [[ -n "$GEN_PID" ]] && kill "$GEN_PID" 2>/dev/null
  [[ -n "$PING_PID" ]] && kill "$PING_PID" 2>/dev/null
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null
  [[ -n "$ENGINE_PID" ]] && kill "$ENGINE_PID" 2>/dev/null
  [[ -n "$JAR" ]] && rm -f "$JAR"
  bash "$LAB" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

[[ "$(uname -s)" == "Linux" ]] || { echo "Linux only"; exit 2; }
[[ "$(id -u)" == "0" ]] || { echo "must run as root"; exit 2; }
[[ -f "$OBJ" ]] || { echo "missing $OBJ"; exit 2; }
[[ -x "$BIN" ]] || { echo "missing engine binary $BIN"; exit 2; }
command -v ip >/dev/null || { echo "iproute2 (ip) required"; exit 2; }
command -v python3 >/dev/null || { echo "python3 required"; exit 2; }

echo "== lab up =="
bash "$LAB" up >/dev/null
DEV_MAC=$(ip -n ns-dev link show veth-dev | awk '/link\/ether/{print $2}')
echo "device MAC: $DEV_MAC"

echo "== upstream simulator in ns-net =="
ip netns exec ns-net python3 - <<'PY' >/tmp/netns-device-upstream.log 2>&1 &
import socket
import threading
import time

def tcp_server(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("10.0.1.2", port))
    sock.listen(64)
    while True:
        conn, _ = sock.accept()
        try:
            conn.recv(256)
            conn.sendall(b"ok\n")
        finally:
            conn.close()

def udp_server(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("10.0.1.2", port))
    while True:
        sock.recvfrom(2048)

for p in (443, 4444, 8080):
    threading.Thread(target=tcp_server, args=(p,), daemon=True).start()
for p in (53, 4444):
    threading.Thread(target=udp_server, args=(p,), daemon=True).start()

while True:
    time.sleep(60)
PY
SERVER_PID=$!
sleep 0.5

echo "== starting platform in ns-gw (attach $GW_LAN) =="
ip netns exec ns-gw "$BIN" -fake -db /tmp/netns-device-containment.db \
  -http 127.0.0.1:8080 -pass "$LAB_PASS" -devchoke-obj "$OBJ" -devchoke-iface "$GW_LAN" \
  >/tmp/netns-device-containment-engine.log 2>&1 &
ENGINE_PID=$!

up=0
for _ in $(seq 1 40); do
  if ip netns exec ns-gw curl -s -o /dev/null "$URL/login" 2>/dev/null; then
    up=1
    break
  fi
  sleep 0.25
done
if [[ "$up" != "1" ]]; then
  echo "FAIL: platform did not come up; log:"
  sed 's/^/    /' /tmp/netns-device-containment-engine.log
  exit 1
fi

JAR=$(mktemp)
ip netns exec ns-gw curl -s -c "$JAR" --data-urlencode 'user=admin' \
  --data-urlencode "pass=$LAB_PASS" "$URL/api/login" >/dev/null
CSRF=$(awk '$6=="csrf_token"{print $7}' "$JAR")

GET() { ip netns exec ns-gw curl -s -b "$JAR" "$URL$1"; }
POST() { ip netns exec ns-gw curl -s -b "$JAR" -H "X-CSRF-Token: $CSRF" -H 'content-type: application/json' -X POST "$URL$1" -d "$2"; }
tcp_probe() {
  ip netns exec ns-dev python3 - <<'PY' >/dev/null 2>&1
import socket
s = socket.create_connection(("10.0.1.2", 4444), timeout=1.0)
s.sendall(b"probe\n")
s.recv(16)
s.close()
PY
}

echo "== device traffic generators =="
(while true; do ip netns exec ns-dev ping -c1 -W1 10.0.1.2 >/dev/null 2>&1; sleep 1; done) &
PING_PID=$!

ip netns exec ns-dev python3 - <<'PY' >/tmp/netns-device-generator.log 2>&1 &
import socket
import time

def tcp(ip, port, label):
    try:
        s = socket.create_connection((ip, port), timeout=0.5)
        s.sendall((label + "\n").encode())
        try:
            s.recv(16)
        except Exception:
            pass
        s.close()
    except Exception:
        pass

def udp(ip, port, label):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(label.encode(), (ip, port))
        s.close()
    except Exception:
        pass

while True:
    udp("10.0.1.2", 53, "dns-query")
    tcp("10.0.1.2", 443, "https-session")
    tcp("10.0.1.2", 8080, "unknown-http")
    # Suspicious-looking C2 / reverse-shell style beacon, still only local lab traffic.
    udp("10.0.1.2", 4444, "beacon")
    tcp("10.0.1.2", 4444, "reverse-shell-like-connect")
    time.sleep(0.5)
PY
GEN_PID=$!

echo "== baseline platform observations =="
sleep 3
STATE=$(GET /api/choke/device-state)
echo "  device-state: $STATE"
if printf '%s' "$STATE" | grep -q '"data_plane":"tc"'; then ok "platform reports tc data plane"; else bad "platform reports tc data plane"; fi
if printf '%s' "$STATE" | grep -q '"mode":"detect-only"'; then ok "device gateway starts detect-only"; else bad "device gateway starts detect-only"; fi

FLOWS=$(GET "/api/choke/device-flows?mac=$DEV_MAC")
echo "  device-flows: $FLOWS"
if printf '%s' "$FLOWS" | grep -q '"dest_port":4444'; then ok "platform sees suspicious high-port device flow"; else bad "platform sees suspicious high-port device flow"; fi
if printf '%s' "$FLOWS" | grep -q '"dest_port":443'; then ok "platform also sees benign HTTPS-like device flow"; else bad "platform also sees benign HTTPS-like device flow"; fi

if tcp_probe; then ok "baseline: device can reach suspicious service"; else bad "baseline: device can reach suspicious service"; fi

echo "== contain via platform =="
MODE=$(POST /api/choke/device-mode '{"enforcing":true,"reason":"containment lab"}')
echo "  device-mode: $MODE"
if printf '%s' "$MODE" | grep -q '"mode":"enforcing"'; then ok "platform switched device mode to enforcing"; else bad "platform switched device mode to enforcing"; fi

JAIL=$(POST /api/choke/device-jail "{\"macs\":[\"$DEV_MAC\"],\"action\":\"sever\",\"reason\":\"suspicious beacon to 10.0.1.2:4444\"}")
echo "  device-jail: $JAIL"
sleep 0.75
if tcp_probe; then bad "after sever: device traffic should be blocked"; else ok "after sever: device traffic is blocked"; fi
if GET /api/choke/devices | grep -q '"state":"severed"'; then ok "platform reports device state=severed"; else bad "platform reports device state=severed"; fi

echo "== recover =="
THAW=$(POST /api/choke/device-thaw "{\"mac\":\"$DEV_MAC\",\"reason\":\"containment lab complete\"}")
echo "  device-thaw: $THAW"
sleep 0.75
if tcp_probe; then ok "after thaw: device traffic restored"; else bad "after thaw: device traffic restored"; fi

echo "== result: $PASS passed, $FAIL failed =="
[[ "$FAIL" -eq 0 ]]

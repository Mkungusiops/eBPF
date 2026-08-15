#!/usr/bin/env bash
# netns-demo.sh — launch a browsable live demo of the network choke UI.
#
# Creates ONE isolated "device" (a veth into a netns, with a steady pinger so
# it stays visible), attaches the tc data plane to the device-facing veth, and
# runs the engine on 0.0.0.0:8080 so you can open /devices in a browser and
# actually throttle/sever/thaw the device. Fully isolated on 10.9.0.0/24 — it
# never touches the host's real uplink, so severing the demo device is safe.
#
# Linux + root. Runs the engine in the FOREGROUND; Ctrl-C (or stopping the
# launching task) tears the lab down. Usage:
#   sudo bash scripts/dev/netns-demo.sh [DEVCHOKE_OBJ] [ENGINE_BIN]
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OBJ="${1:-$ROOT/engine/internal/enforce/devbpf/bpf/devchoke.o}"
BIN="${2:-$ROOT/engine/engine-linux-amd64}"
PORT="${PORT:-8080}"   # override if another engine already holds 8080
IFACE=dlan

[[ "$(uname -s)" == "Linux" ]] || { echo "Linux only"; exit 2; }
[[ "$(id -u)" == "0" ]]        || { echo "must run as root"; exit 2; }
[[ -f "$OBJ" ]] || { echo "missing $OBJ — run: make devchoke"; exit 2; }
[[ -x "$BIN" ]] || { echo "missing $BIN — run: make build-linux"; exit 2; }

PINGER=""; GEN=""
cleanup() {
  [[ -n "$PINGER" ]] && kill "$PINGER" 2>/dev/null
  [[ -n "$GEN" ]] && kill "$GEN" 2>/dev/null
  ip netns del demo-dev 2>/dev/null || true
  ip link del "$IFACE" 2>/dev/null || true
}
trap cleanup EXIT
cleanup   # clear any prior run

# Isolated device on 10.9.0.0/24: dlan (host side) <-> ddev (in demo-dev).
# A default route via the host side means the device's traffic to arbitrary
# destinations egresses ddev and ingresses dlan (where the data plane records
# the flow) even though it goes nowhere — perfect for a self-contained demo.
ip netns add demo-dev
ip link add "$IFACE" type veth peer name ddev
ip link set ddev netns demo-dev
ip addr add 10.9.0.1/24 dev "$IFACE"
ip link set "$IFACE" up
ip netns exec demo-dev ip addr add 10.9.0.2/24 dev ddev
ip netns exec demo-dev ip link set ddev up
ip netns exec demo-dev ip link set lo up
ip netns exec demo-dev ip route add default via 10.9.0.1 2>/dev/null || true

DEV_MAC=$(ip -n demo-dev link show ddev | grep -o "link/ether [^ ]*" | cut -d" " -f2)

# Steady pinger keeps the device visible (and visibly drops on sever).
( while true; do ip netns exec demo-dev ping -c1 -W1 10.9.0.1 >/dev/null 2>&1; sleep 1; done ) &
PINGER=$!

# Traffic generator: the device "talks to" a few representative destinations
# so the per-device connections view is populated — benign DNS/HTTPS plus a
# suspicious high port (:4444) you can spot and choke on.
cat > /tmp/devgen.py <<'PY'
import socket, time
udp = [("8.8.8.8", 53), ("9.9.9.9", 53), ("203.0.113.7", 4444)]
tcp = [("1.1.1.1", 443), ("93.184.216.34", 80), ("203.0.113.7", 4444)]
while True:
    for ip, p in udp:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b"x", (ip, p)); s.close()
        except Exception:
            pass
    for ip, p in tcp:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(0.3); s.connect((ip, p))
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass
    time.sleep(2)
PY
( ip netns exec demo-dev python3 /tmp/devgen.py >/dev/null 2>&1 ) &
GEN=$!

echo "──────────────────────────────────────────────────────────────"
echo " Network choke demo up. Demo device MAC: $DEV_MAC (10.9.0.2)"
echo " Open:  http://<this-host>:$PORT/devices   login: admin / ${NETNS_PASS:-netns-dev}"
echo " Select the device row → Choke (sever) to terminate it; Thaw to restore."
echo "──────────────────────────────────────────────────────────────"

echo " (engine log → /tmp/ui-demo.log inside the VM)"
echo "──────────────────────────────────────────────────────────────"
# Engine output goes to a VM-side file (it's chatty in -fake mode); the
# launcher's stdout stays a one-time banner.
exec "$BIN" -fake -db /tmp/ui-demo.db -http 0.0.0.0:$PORT \
  -pass ${NETNS_PASS:-netns-dev} \
  -devchoke-obj "$OBJ" -devchoke-iface "$IFACE" >>/tmp/ui-demo.log 2>&1

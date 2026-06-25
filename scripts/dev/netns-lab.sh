#!/usr/bin/env bash
# netns-lab.sh — a 3-namespace lab for the network (per-device) choke.
#
#   ns-dev  <veth>  ns-gw (ip_forward + NAT, runs the engine)  <veth>  ns-net
#
# This reproduces FORWARDED traffic — exactly what the cgroup/connect hooks
# can't see and the tc devchoke data plane can. The engine runs inside ns-gw
# and attaches to veth-gw-lan (the "LAN" side); ns-dev is the device you
# choke, ns-net is the upstream.
#
# Usage:
#   sudo bash scripts/dev/netns-lab.sh up        # build the lab
#   sudo bash scripts/dev/netns-lab.sh ping      # dev -> upstream sanity
#   sudo bash scripts/dev/netns-lab.sh mac       # print the device MAC
#   sudo bash scripts/dev/netns-lab.sh run OBJ   # run the engine in ns-gw
#                                                #   OBJ = path to devchoke.o
#   sudo bash scripts/dev/netns-lab.sh down      # tear it all down
#
# Then drive it: curl -u admin:ebpf-soc-demo http://127.0.0.1:8080/api/choke/devices
# (the engine's :8080 is reachable from the host since ns-gw shares nothing
# but the veths — run curl with `sudo ip netns exec ns-gw curl ...`).
set -euo pipefail

GW_LAN=veth-gw-lan
GW_WAN=veth-gw-wan

up() {
  down >/dev/null 2>&1 || true
  ip netns add ns-dev
  ip netns add ns-gw
  ip netns add ns-net

  ip link add veth-dev type veth peer name "$GW_LAN"
  ip link set veth-dev netns ns-dev
  ip link set "$GW_LAN" netns ns-gw

  ip link add "$GW_WAN" type veth peer name veth-net
  ip link set "$GW_WAN" netns ns-gw
  ip link set veth-net netns ns-net

  ip -n ns-dev addr add 10.0.0.2/24 dev veth-dev
  ip -n ns-dev link set veth-dev up
  ip -n ns-dev link set lo up
  ip -n ns-dev route add default via 10.0.0.1

  ip -n ns-gw addr add 10.0.0.1/24 dev "$GW_LAN"
  ip -n ns-gw addr add 10.0.1.1/24 dev "$GW_WAN"
  ip -n ns-gw link set "$GW_LAN" up
  ip -n ns-gw link set "$GW_WAN" up
  ip -n ns-gw link set lo up
  ip netns exec ns-gw sysctl -qw net.ipv4.ip_forward=1
  ip netns exec ns-gw iptables -t nat -A POSTROUTING -o "$GW_WAN" -j MASQUERADE 2>/dev/null || \
    ip netns exec ns-gw nft add table ip nat 2>/dev/null || true

  ip -n ns-net addr add 10.0.1.2/24 dev veth-net
  ip -n ns-net link set veth-net up
  ip -n ns-net link set lo up
  ip -n ns-net route add default via 10.0.1.1

  echo "lab up. device MAC: $(mac)"
  echo "attach interface for the engine: $GW_LAN (inside ns-gw)"
}

mac() { ip -n ns-dev link show veth-dev | awk '/link\/ether/{print $2}'; }

ping_test() {
  echo "dev -> upstream:"
  ip netns exec ns-dev ping -c2 -W1 10.0.1.2
}

run() {
  local obj="${1:-}"
  if [[ -z "$obj" ]]; then echo "usage: netns-lab.sh run /path/to/devchoke.o"; exit 1; fi
  local bin
  bin="$(cd "$(dirname "$0")/../../engine" && pwd)/engine-linux-amd64"
  [[ -x "$bin" ]] || bin="$(cd "$(dirname "$0")/../../engine" && pwd)/engine"
  echo "running engine in ns-gw, attaching devchoke to $GW_LAN ..."
  exec ip netns exec ns-gw "$bin" \
    -fake \
    -db /tmp/netns-lab-events.db \
    -http :8080 \
    -devchoke-obj "$obj" \
    -devchoke-iface "$GW_LAN"
}

down() {
  for n in ns-dev ns-gw ns-net; do ip netns del "$n" 2>/dev/null || true; done
  echo "lab down."
}

case "${1:-}" in
  up)   up ;;
  ping) ping_test ;;
  mac)  mac ;;
  run)  shift; run "$@" ;;
  down) down ;;
  *) echo "usage: $0 {up|ping|mac|run OBJ|down}"; exit 1 ;;
esac

// Package tetrabridge turns Tetragon gRPC events into the console's broadcast
// shape.
//
// It exists because cmd/engine and cmd/agent each carried a byte-identical copy
// of this logic. The STRANGLER NOTE in cmd/agent/main.go calls that duplication
// "the accepted, temporary cost… until Phase 1", but Phase 1 has shipped and the
// copies have already drifted elsewhere in the tree — a bug fixed in one binary
// and missed in its twin is how the fleet view came to report an audit check
// that never ran as passing. Shared code cannot drift.
package tetrabridge

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/jeffmk/ebpf-poc-engine/internal/api"
)

// Send offers b to ch without blocking.
//
// The event loop must never stall on a slow console subscriber: dropping a UI
// update is recoverable, wedging the loop that feeds enforcement is not.
// broadcastDropped counts SSE frames discarded because a subscriber could not
// keep up.
//
// The drop itself is correct — blocking the event loop on a slow browser would
// stall sensing — but it was SILENT, and "are you dropping events?" is the
// question a customer asks before putting an agent on production hosts. An
// uncounted drop means the honest answer was "we don't know".
var broadcastDropped atomic.Uint64

// BroadcastDropped reports how many live-stream frames have been discarded
// since start. Surfaced on the sensor-health endpoint.
func BroadcastDropped() uint64 { return broadcastDropped.Load() }

func Send(ch chan<- api.Broadcast, b api.Broadcast) {
	select {
	case ch <- b:
	default:
		// Drop on overflow rather than block the event loop — but count it.
		broadcastDropped.Add(1)
	}
}

// HandleExit broadcasts a process_exit event.
func HandleExit(ev *tetragon.ProcessExit, broadcast chan<- api.Broadcast) {
	if ev == nil || ev.Process == nil {
		return
	}
	p := ev.Process
	Send(broadcast, api.Broadcast{Type: "process_exit", Payload: map[string]interface{}{
		"exec_id": p.ExecId,
		"pid":     p.Pid.GetValue(),
		"binary":  p.Binary,
	}})
}

// JoinHostPort renders a peer endpoint, omitting a zero port.
func JoinHostPort(addr string, port uint32) string {
	if port == 0 {
		return addr
	}
	// IPv6 must be bracketed, exactly as net.JoinHostPort does — this function
	// borrowed that name while omitting the one rule that makes the output
	// parseable.
	//
	// Without it a loopback health check renders as "::1:8090", which nothing
	// downstream can split: an address and a port are separated by a colon,
	// and so are the eight groups of an IPv6 address. The console's peer
	// parser took everything before the first colon, got the empty string,
	// and so classified localhost as neither loopback nor a LAN device —
	// leaving "external peer", which is how a health check to your own machine
	// gets drawn on the correlation graph as an outbound connection.
	//
	// Latent until now: nothing that made IPv6 connections was in the
	// outbound-connections binary list. Adding curl to that list made it
	// reachable on every host, several times a minute.
	if strings.Contains(addr, ":") {
		return fmt.Sprintf("[%s]:%d", addr, port)
	}
	return fmt.Sprintf("%s:%d", addr, port)
}

// ExtractKprobePeer returns the remote endpoint a kprobe touched, or an empty
// address when it touched none.
//
// The sensor has this STRUCTURED — a sock or sockaddr argument with a distinct
// address and port — and ExtractKprobeArgs then flattens it into the args
// blob. Everything downstream that wanted "what did this talk to" had to
// recover it by pattern-matching free text, so the console's Network
// Connections panel silently missed anything whose rendering did not match,
// while its title claimed the peers were observed.
//
// Same traversal order as ExtractKprobeArgs so the two cannot disagree about
// which argument is the peer.
// Returned as address and port rather than a joined string: the wire
// ProcessEvent already models them separately (dest_ip, dest_port) and has
// since it shipped — those fields were simply never populated. Joining here
// only to split again at the uplink would be a round trip through a format
// nobody needs.
func ExtractKprobePeer(args []*tetragon.KprobeArgument) (addr string, port uint32) {
	for _, a := range args {
		if s := a.GetSockArg(); s != nil && s.GetDaddr() != "" {
			return s.GetDaddr(), s.GetDport()
		}
		if sa := a.GetSockaddrArg(); sa != nil && sa.GetAddr() != "" {
			return sa.GetAddr(), sa.GetPort()
		}
	}
	return "", 0
}

// ExtractKprobeArgs flattens a kprobe's typed arguments into the space-joined
// string the console renders as Args.
func ExtractKprobeArgs(args []*tetragon.KprobeArgument) string {
	parts := make([]string, 0, len(args))
	for _, a := range args {
		if a == nil {
			continue
		}
		if f := a.GetFileArg(); f != nil && f.Path != "" {
			parts = append(parts, f.Path)
			continue
		}
		if p := a.GetPathArg(); p != nil && p.Path != "" {
			parts = append(parts, p.Path)
			continue
		}
		if s := a.GetStringArg(); s != "" {
			parts = append(parts, s)
			continue
		}
		// Network arguments (tcp_connect's `sock`, or a `sockaddr`). Without
		// this the destination IP is dropped: an outbound-connections event
		// carries only its policy name, no peer, so the correlation graph can
		// never draw an IP node for it. Rendering the remote endpoint as
		// "daddr:dport" puts it into Args, where the console's IOC/peer
		// extraction picks it up.
		if s := a.GetSockArg(); s != nil && s.GetDaddr() != "" {
			parts = append(parts, JoinHostPort(s.GetDaddr(), s.GetDport()))
			continue
		}
		if sa := a.GetSockaddrArg(); sa != nil && sa.GetAddr() != "" {
			parts = append(parts, JoinHostPort(sa.GetAddr(), sa.GetPort()))
			continue
		}
		if v := a.GetIntArg(); v != 0 {
			parts = append(parts, fmt.Sprintf("%d", v))
			continue
		}
	}
	return strings.Join(parts, " ")
}

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

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/jeffmk/ebpf-poc-engine/internal/api"
)

// Send offers b to ch without blocking.
//
// The event loop must never stall on a slow console subscriber: dropping a UI
// update is recoverable, wedging the loop that feeds enforcement is not.
func Send(ch chan<- api.Broadcast, b api.Broadcast) {
	select {
	case ch <- b:
	default:
		// drop on overflow rather than block the event loop
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
	return fmt.Sprintf("%s:%d", addr, port)
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

package tetrabridge

import (
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

// The sensor has the peer STRUCTURED — a sock or sockaddr argument with a
// distinct address and port — and ExtractKprobeArgs flattens it into a text
// blob. Everything downstream that wanted "what did this talk to" then had to
// recover it by pattern-matching free text.

func sockArg(daddr string, dport uint32) *tetragon.KprobeArgument {
	return &tetragon.KprobeArgument{Arg: &tetragon.KprobeArgument_SockArg{
		SockArg: &tetragon.KprobeSock{Daddr: daddr, Dport: dport}}}
}

func TestPeerIsExtractedStructurally(t *testing.T) {
	addr, port := ExtractKprobePeer([]*tetragon.KprobeArgument{
		{Arg: &tetragon.KprobeArgument_StringArg{StringArg: "-s"}},
		sockArg("203.0.113.10", 443),
	})
	if addr != "203.0.113.10" || port != 443 {
		t.Fatalf("got %q:%d, want the sock argument's endpoint", addr, port)
	}
}

func TestAKprobeWithNoNetworkArgumentHasNoPeer(t *testing.T) {
	addr, port := ExtractKprobePeer([]*tetragon.KprobeArgument{
		{Arg: &tetragon.KprobeArgument_StringArg{StringArg: "/etc/shadow"}},
	})
	if addr != "" || port != 0 {
		t.Fatalf("got %q:%d, want no peer for a file access", addr, port)
	}
}

func TestTheFlattenedArgsStillCarryThePeer(t *testing.T) {
	// Args keeps it too, so nothing reading the flattened form regresses and
	// events stored before the column existed still resolve by fallback.
	got := ExtractKprobeArgs([]*tetragon.KprobeArgument{sockArg("203.0.113.10", 443)})
	if got != "203.0.113.10:443" {
		t.Fatalf("args = %q, want the peer still rendered", got)
	}
}

package tetrabridge

import (
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/jeffmk/ebpf-poc-engine/internal/api"
)

// This logic lived twice inside two 1,000+ line main() functions, where it was
// unreachable from a test. Extracting it is what makes these assertions possible
// at all — and the peer-rendering case below is one the console depends on.

func TestJoinHostPortOmitsAZeroPort(t *testing.T) {
	if got := JoinHostPort("10.0.0.9", 0); got != "10.0.0.9" {
		t.Errorf("JoinHostPort(_, 0) = %q, want bare address", got)
	}
	if got := JoinHostPort("10.0.0.9", 443); got != "10.0.0.9:443" {
		t.Errorf("JoinHostPort = %q, want 10.0.0.9:443", got)
	}
}

// Without the sock/sockaddr branches an outbound-connection event carries only
// its policy name and no peer, so the correlation graph can never draw an IP
// node for it.
func TestExtractKprobeArgsRendersNetworkPeers(t *testing.T) {
	args := []*tetragon.KprobeArgument{
		nil, // must be skipped, not panicked on
		{Arg: &tetragon.KprobeArgument_SockArg{SockArg: &tetragon.KprobeSock{
			Daddr: "203.0.113.7", Dport: 8443,
		}}},
		{Arg: &tetragon.KprobeArgument_StringArg{StringArg: "/etc/shadow"}},
	}
	got := ExtractKprobeArgs(args)
	want := "203.0.113.7:8443 /etc/shadow"
	if got != want {
		t.Errorf("ExtractKprobeArgs = %q, want %q", got, want)
	}
}

func TestExtractKprobeArgsOnEmptyInput(t *testing.T) {
	if got := ExtractKprobeArgs(nil); got != "" {
		t.Errorf("ExtractKprobeArgs(nil) = %q, want empty", got)
	}
}

// Dropping a console update is recoverable; wedging the loop that feeds
// enforcement is not. Send must never block on a full channel.
func TestSendDropsRatherThanBlocking(t *testing.T) {
	ch := make(chan api.Broadcast, 1)
	Send(ch, api.Broadcast{Type: "first"})
	done := make(chan struct{})
	go func() {
		Send(ch, api.Broadcast{Type: "second"}) // channel is full
		close(done)
	}()
	select {
	case <-done:
	default:
		<-done // give the goroutine a moment; a block here fails the test by timeout
	}
	if got := (<-ch).Type; got != "first" {
		t.Errorf("buffered broadcast = %q, want first", got)
	}
}

func TestHandleExitIgnoresIncompleteEvents(t *testing.T) {
	ch := make(chan api.Broadcast, 4)
	HandleExit(nil, ch)
	HandleExit(&tetragon.ProcessExit{}, ch) // no Process
	if len(ch) != 0 {
		t.Fatalf("%d broadcasts from incomplete events, want 0", len(ch))
	}

	HandleExit(&tetragon.ProcessExit{Process: &tetragon.Process{
		ExecId: "exec-1", Pid: wrapperspb.UInt32(4242), Binary: "/usr/bin/curl",
	}}, ch)
	if len(ch) != 1 {
		t.Fatalf("%d broadcasts, want 1", len(ch))
	}
	b := <-ch
	if b.Type != "process_exit" {
		t.Errorf("type = %q, want process_exit", b.Type)
	}
	payload, ok := b.Payload.(map[string]interface{})
	if !ok {
		t.Fatalf("payload type %T", b.Payload)
	}
	if payload["exec_id"] != "exec-1" || payload["pid"] != uint32(4242) {
		t.Errorf("payload = %v", payload)
	}
}

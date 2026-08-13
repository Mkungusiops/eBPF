package command

import (
	"context"
	"errors"
	"io"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
)

// RunCommands is the agent side of the command channel: it opens the stream,
// receives commands, runs each through the Processor (verify → guardrails →
// apply), and sends the resulting ack back. It returns when the server closes
// the stream (io.EOF) or on a transport error; the caller reconnects.
//
// Autonomy: this only receives/applies control-plane commands. A down control
// plane simply means no new commands arrive — the agent keeps enforcing its
// last-applied local policy.
func RunCommands(ctx context.Context, cc ebpfsocv1.CommandServiceClient, proc *Processor) error {
	stream, err := cc.Commands(ctx)
	if err != nil {
		return err
	}
	for {
		cmd, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := stream.Send(proc.Handle(cmd)); err != nil {
			return err
		}
	}
}

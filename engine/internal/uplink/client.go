package uplink

import (
	"context"
	"errors"
	"io"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
)

// DrainOnce ships every currently-buffered record to the control plane over a
// single StreamTelemetry stream, advancing the Buffer as cumulative acks
// arrive, then returns when the Buffer is empty (or on the first transport
// error). maxBatch bounds records per batch (backpressure).
//
// Resumability + autonomy (wire-contract.md §4, §6): DrainOnce never removes a
// record until it is acked, so a transport error simply returns and the caller
// reconnects — the un-acked tail stays buffered and is re-sent on the next
// DrainOnce, which the collector dedups. And because this is only the shipping
// path, a control plane that is down or slow can never stall the agent: the
// caller keeps enqueuing telemetry and enforcing regardless.
func DrainOnce(ctx context.Context, client ebpfsocv1.TelemetryServiceClient, buf *Buffer, maxBatch int) error {
	if maxBatch <= 0 {
		return errors.New("uplink: maxBatch must be > 0")
	}
	stream, err := client.StreamTelemetry(ctx)
	if err != nil {
		return err
	}
	for {
		batch := buf.NextBatch(maxBatch)
		if batch == nil {
			// Nothing left to send. Half-close and drain any trailing acks.
			if err := stream.CloseSend(); err != nil {
				return err
			}
			for {
				ack, err := stream.Recv()
				if errors.Is(err, io.EOF) {
					return nil
				}
				if err != nil {
					return err
				}
				buf.Ack(ack.GetAckedThroughSeq())
			}
		}
		if err := stream.Send(batch); err != nil {
			return err
		}
		ack, err := stream.Recv()
		if err != nil {
			return err
		}
		buf.Ack(ack.GetAckedThroughSeq())
	}
}

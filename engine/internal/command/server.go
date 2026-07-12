package command

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/mtls"
	"github.com/jeffmk/ebpf-poc-engine/internal/signing"
)

// Dispatcher is the control-plane side of the command channel: it SIGNS
// commands, queues them per agent, streams them to a connected agent, and
// records the agent's acks (audited on both ends — threat-model CH-5). It
// implements ebpfsocv1.CommandServiceServer.
type Dispatcher struct {
	ebpfsocv1.UnimplementedCommandServiceServer

	signer  signing.Signer
	signTTL time.Duration

	mu     sync.Mutex
	queues map[string][]*ebpfsocv1.Command // agent_id → pending
	acks   map[string]*ebpfsocv1.CommandAck
}

func NewDispatcher(signer signing.Signer, signTTL time.Duration) *Dispatcher {
	return &Dispatcher{
		signer:  signer,
		signTTL: signTTL,
		queues:  make(map[string][]*ebpfsocv1.Command),
		acks:    make(map[string]*ebpfsocv1.CommandAck),
	}
}

// Enqueue assigns an id + expiry, signs the command over its canonical bytes,
// and queues it for agentID. Returns the command id.
func (d *Dispatcher) Enqueue(agentID string, c *ebpfsocv1.Command) string {
	if c.GetCommandId() == "" {
		c.CommandId = newCommandID()
	}
	c.IssuedAt = timestamppb.Now()
	if c.GetExpiresAt() == nil {
		c.ExpiresAt = timestamppb.New(time.Now().Add(d.signTTL))
	}
	c.Signature = d.signer.Sign(Canonical(c))
	d.mu.Lock()
	d.queues[agentID] = append(d.queues[agentID], c)
	d.mu.Unlock()
	return c.GetCommandId()
}

// Ack returns the recorded ack for a command id.
func (d *Dispatcher) Ack(commandID string) (*ebpfsocv1.CommandAck, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	a, ok := d.acks[commandID]
	return a, ok
}

func (d *Dispatcher) dequeue(agentID string) []*ebpfsocv1.Command {
	d.mu.Lock()
	defer d.mu.Unlock()
	cmds := d.queues[agentID]
	delete(d.queues, agentID)
	return cmds
}

func (d *Dispatcher) recordAck(a *ebpfsocv1.CommandAck) {
	d.mu.Lock()
	d.acks[a.GetCommandId()] = a
	d.mu.Unlock()
}

// Commands streams the agent's queued commands and records its acks. The agent
// is identified by its mTLS certificate (never a request field). This minimal
// Phase 1 form sends the currently-queued commands, then collects one ack per
// command; a durable, long-lived push loop lands with the fleet service.
func (d *Dispatcher) Commands(stream ebpfsocv1.CommandService_CommandsServer) error {
	_, agent, err := mtls.PeerTenant(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	cmds := d.dequeue(agent)
	for _, c := range cmds {
		if err := stream.Send(c); err != nil {
			return err
		}
	}
	for range cmds {
		ack, err := stream.Recv()
		if err != nil {
			return err
		}
		d.recordAck(ack)
	}
	return nil
}

func newCommandID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "cmd-" + hex.EncodeToString(b)
}

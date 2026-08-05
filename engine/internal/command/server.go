package command

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
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
	// waiters lets Enqueue wake an agent that is parked in Commands with an
	// empty queue, so a command dispatched while the agent is idle goes out
	// immediately instead of waiting for the agent's next reconnect.
	waiters map[string][]chan struct{}
}

// IdlePollWindow bounds how long Commands parks an agent with nothing queued.
// The agent reconnects when it elapses, so this is just a liveness ceiling —
// commands are delivered by the waiter wake-up, not by this timer.
const IdlePollWindow = 25 * time.Second

func NewDispatcher(signer signing.Signer, signTTL time.Duration) *Dispatcher {
	return &Dispatcher{
		signer:  signer,
		signTTL: signTTL,
		queues:  make(map[string][]*ebpfsocv1.Command),
		acks:    make(map[string]*ebpfsocv1.CommandAck),
		waiters: make(map[string][]chan struct{}),
	}
}

// subscribe registers a wake-up channel for agentID, returning it plus the
// function that removes it again.
func (d *Dispatcher) subscribe(agentID string) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	d.mu.Lock()
	d.waiters[agentID] = append(d.waiters[agentID], ch)
	d.mu.Unlock()
	return ch, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		w := d.waiters[agentID]
		for i, c := range w {
			if c == ch {
				d.waiters[agentID] = append(w[:i], w[i+1:]...)
				break
			}
		}
		if len(d.waiters[agentID]) == 0 {
			delete(d.waiters, agentID)
		}
	}
}

// wake signals every stream parked on agentID. Non-blocking: the channels are
// buffered depth-1, so a pending wake-up is enough — the receiver re-drains the
// whole queue anyway.
func (d *Dispatcher) wake(agentID string) {
	for _, ch := range d.waiters[agentID] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Enqueue assigns an id + expiry, signs the command over its canonical bytes,
// and queues it for agentID. Returns the command id.
//
// The command id identifies ONE DISPATCH TO ONE AGENT, not the action, so each
// call mints a fresh id and queues its own copy of c. Both matter when a caller
// sends the same action to several agents:
//
//   - reusing the id would make every agent's ack land on the same key, so only
//     one would ever be observed and it would be attributed to whichever agent
//     was enqueued last. A caller fanning a containment command out to a tenant
//     could not tell which host actually enforced.
//   - mutating c in place would alias the queued commands, so signing the
//     second dispatch would retroactively rewrite the first agent's id.
//
// Callers therefore cannot pre-set a command id; nothing needs to, and allowing
// it is what made the aliasing silent.
func (d *Dispatcher) Enqueue(agentID string, c *ebpfsocv1.Command) string {
	cmd, _ := proto.Clone(c).(*ebpfsocv1.Command)
	cmd.CommandId = newCommandID()
	cmd.IssuedAt = timestamppb.Now()
	if cmd.GetExpiresAt() == nil {
		cmd.ExpiresAt = timestamppb.New(time.Now().Add(d.signTTL))
	}
	cmd.Signature = d.signer.Sign(Canonical(cmd))
	d.mu.Lock()
	d.queues[agentID] = append(d.queues[agentID], cmd)
	d.wake(agentID)
	d.mu.Unlock()
	return cmd.GetCommandId()
}

// Pending is the number of commands queued for an agent that it has not yet
// been sent. Zero for a connected, idle agent — Enqueue hands the command
// straight to the parked stream. A non-zero, non-decreasing value means an agent
// is not collecting its commands, which is also what change-control tests assert
// against when proving a held action was never dispatched.
func (d *Dispatcher) Pending(agentID string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.queues[agentID])
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
// is identified by its mTLS certificate (never a request field).
//
// An agent that connects with nothing queued PARKS here (up to IdlePollWindow)
// instead of being closed straight away. That is what makes dispatch prompt: the
// previous form returned immediately, so an idle agent spent most of its life
// between streams — a command enqueued in that gap waited for the agent's
// reconnect backoff and routinely missed the caller's ack deadline, which made
// the operator-visible "applied" flag a coin flip. Enqueue now wakes the parked
// stream and the command goes out at once.
func (d *Dispatcher) Commands(stream ebpfsocv1.CommandService_CommandsServer) error {
	_, agent, err := mtls.PeerTenant(stream.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	wake, unsubscribe := d.subscribe(agent)
	defer unsubscribe()

	cmds := d.dequeue(agent)
	if len(cmds) == 0 {
		select {
		case <-wake:
			cmds = d.dequeue(agent)
		case <-time.After(IdlePollWindow):
			return nil // nothing to do; the agent redials
		case <-stream.Context().Done():
			return nil
		}
	}
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

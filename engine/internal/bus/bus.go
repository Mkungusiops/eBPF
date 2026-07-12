// Package bus decouples ingest from processing (architecture.md §3.2): the
// collector publishes tenant-stamped records, and downstream consumers (central
// store today; detection later) subscribe. It absorbs spikes and enables replay.
//
// TENANCY: the tenant is stamped by the ingest collector from the mTLS cert
// (Layer 2) BEFORE publish, so it is authoritative here. The routing subject is
// per-tenant, which lets a bus with per-tenant authorization (NATS accounts /
// Kafka ACLs) enforce isolation at the transport layer too, and lets replay be
// scoped per tenant. Consumers preserve the stamp into the tenant-scoped store
// (Layer 3), so isolation holds across the decoupling.
//
// The concrete backend is NATS JetStream (docs/plan/d4c-tech-decisions.md §3.1;
// Apache-2.0, self-hostable). This package defines the interface plus an
// in-memory implementation used for tests and the single-node path; the NATS
// adapter implements the same interface.
package bus

import (
	"errors"
	"strings"
	"sync"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/ingest"
)

// Message is a tenant-stamped telemetry record on the bus. It is exactly the
// collector's stamped record, so ingest → bus is a zero-conversion hop.
type Message = ingest.StampedRecord

// ErrClosed is returned by a closed bus.
var ErrClosed = errors.New("bus: closed")

// Publisher publishes stamped records.
type Publisher interface {
	Publish(Message) error
	Close() error
}

// Handler processes one delivered message.
type Handler func(Message) error

// Subscriber consumes messages, invoking handler for each; Subscribe returns a
// stop function that unsubscribes.
type Subscriber interface {
	Subscribe(handler Handler) (stop func(), err error)
}

// Bus is a publish/subscribe transport.
type Bus interface {
	Publisher
	Subscriber
}

// Subject is the per-tenant routing subject for a record:
// "telemetry.<tenant>.<kind>". Tenant-partitioned so per-tenant bus
// authorization and per-tenant replay are possible.
func Subject(m Message) string {
	return "telemetry." + sanitize(m.TenantID) + "." + kindOf(m.Record)
}

func kindOf(rec *ebpfsocv1.TelemetryRecord) string {
	switch rec.GetPayload().(type) {
	case *ebpfsocv1.TelemetryRecord_Event:
		return "event"
	case *ebpfsocv1.TelemetryRecord_Alert:
		return "alert"
	case *ebpfsocv1.TelemetryRecord_Decision:
		return "decision"
	default:
		return "unknown"
	}
}

// sanitize keeps a tenant id usable as a single subject token (subjects are
// dot-delimited). Tenant ids are opaque; we only guard the delimiter.
func sanitize(tenant string) string {
	if tenant == "" {
		return "_none"
	}
	return strings.ReplaceAll(tenant, ".", "_")
}

// Sink adapts a Publisher to ingest.Sink, so the collector publishes to the bus
// instead of writing storage directly.
type Sink struct{ pub Publisher }

var _ ingest.Sink = (*Sink)(nil)

func NewSink(pub Publisher) *Sink { return &Sink{pub: pub} }

func (s *Sink) Put(r ingest.StampedRecord) error { return s.pub.Publish(r) }

// Consume subscribes b and writes every message to a downstream ingest.Sink
// (e.g. the central store), preserving the tenant stamp. It returns the
// subscription's stop function.
func Consume(b Subscriber, downstream ingest.Sink) (stop func(), err error) {
	return b.Subscribe(func(m Message) error { return downstream.Put(m) })
}

// ---- in-memory implementation (tests + single-node path) ------------------

// MemBus is an in-memory Bus. It is deliberately simple: buffered per-subscriber
// channels drained by one goroutine each. The real durability, replay, and
// per-tenant isolation come from the NATS JetStream backend; this exists so the
// ingest→bus→store pipeline is testable in-process.
type MemBus struct {
	mu     sync.RWMutex
	subs   map[int]chan Message
	nextID int
	closed bool
	wg     sync.WaitGroup
}

func NewMemBus() *MemBus { return &MemBus{subs: make(map[int]chan Message)} }

func (b *MemBus) Publish(m Message) error {
	// RLock lets publishes run concurrently but excludes Close/stop (Lock), so a
	// subscriber channel can never be closed mid-send.
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return ErrClosed
	}
	for _, ch := range b.subs {
		ch <- m
	}
	return nil
}

func (b *MemBus) Subscribe(h Handler) (func(), error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, ErrClosed
	}
	id := b.nextID
	b.nextID++
	ch := make(chan Message, 4096)
	b.subs[id] = ch
	b.mu.Unlock()

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		for m := range ch {
			_ = h(m)
		}
	}()

	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			if c, ok := b.subs[id]; ok {
				delete(b.subs, id)
				close(c)
			}
			b.mu.Unlock()
		})
	}, nil
}

func (b *MemBus) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	for id, ch := range b.subs {
		delete(b.subs, id)
		close(ch)
	}
	b.mu.Unlock()
	b.wg.Wait()
	return nil
}

// Package natsbus is the NATS JetStream implementation of bus.Bus
// (docs/plan/d4c-tech-decisions.md §3.1 — NATS JetStream, Apache-2.0,
// self-hostable). It is deliberately isolated in its own package so ONLY the
// control plane links the NATS client; the agent never imports it and stays a
// lean, static CGO-free binary.
//
// Records are published to per-tenant subjects (bus.Subject) under one
// TELEMETRY stream, giving durable, replayable, per-tenant-scoped delivery. The
// tenant/agent stamp travels in message headers; the payload is the marshalled
// TelemetryRecord.
package natsbus

import (
	"context"
	"errors"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"google.golang.org/protobuf/proto"

	ebpfsocv1 "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1"
	"github.com/jeffmk/ebpf-poc-engine/internal/bus"
)

const (
	streamName     = "TELEMETRY"
	streamSubjects = "telemetry.>"
	consumerName   = "central-store"
	hdrTenant      = "Tenant"
	hdrAgent       = "Agent"
)

// Bus is a NATS JetStream bus.Bus.
type Bus struct {
	nc *nats.Conn
	js jetstream.JetStream
}

var _ bus.Bus = (*Bus)(nil)

// Connect dials NATS at url and ensures the telemetry stream exists.
func Connect(url string) (*Bus, error) {
	nc, err := nats.Connect(url)
	if err != nil {
		return nil, err
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = js.CreateStream(ctx, jetstream.StreamConfig{
		Name:      streamName,
		Subjects:  []string{streamSubjects},
		Retention: jetstream.LimitsPolicy,
	})
	if err != nil && !errors.Is(err, jetstream.ErrStreamNameAlreadyInUse) {
		nc.Close()
		return nil, err
	}
	return &Bus{nc: nc, js: js}, nil
}

// Publish sends a stamped record to its per-tenant subject.
func (b *Bus) Publish(m bus.Message) error {
	data, err := proto.Marshal(m.Record)
	if err != nil {
		return err
	}
	msg := &nats.Msg{
		Subject: bus.Subject(m),
		Header:  nats.Header{hdrTenant: []string{m.TenantID}, hdrAgent: []string{m.AgentID}},
		Data:    data,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = b.js.PublishMsg(ctx, msg)
	return err
}

// Subscribe creates a durable consumer over all tenants and invokes handler for
// each message, acking on success and nak'ing on handler error (redelivery).
func (b *Bus) Subscribe(h bus.Handler) (func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cons, err := b.js.CreateOrUpdateConsumer(ctx, streamName, jetstream.ConsumerConfig{
		Durable:       consumerName,
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: streamSubjects,
	})
	if err != nil {
		return nil, err
	}
	cctx, err := cons.Consume(func(msg jetstream.Msg) {
		rec := &ebpfsocv1.TelemetryRecord{}
		if err := proto.Unmarshal(msg.Data(), rec); err != nil {
			_ = msg.Term() // poison message — do not redeliver
			return
		}
		m := bus.Message{
			TenantID: msg.Headers().Get(hdrTenant),
			AgentID:  msg.Headers().Get(hdrAgent),
			Record:   rec,
		}
		if err := h(m); err != nil {
			_ = msg.Nak() // transient — redeliver
			return
		}
		_ = msg.Ack()
	})
	if err != nil {
		return nil, err
	}
	return func() { cctx.Stop() }, nil
}

// Close tears down the NATS connection.
func (b *Bus) Close() error {
	b.nc.Close()
	return nil
}

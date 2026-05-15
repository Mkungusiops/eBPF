// Package metrics is the engine's OpenTelemetry instrumentation.
//
// The exported package-level vars (EventsTotal, AlertsTotal, etc.) are
// populated once Init() runs; before that they're nil and the safeAdd /
// safeRecord helpers no-op. This lets call sites elsewhere in the engine
// instrument unconditionally — main.go can decide at startup whether to
// turn on the meter (e.g. -otlp-endpoint=stdout for dev, OTLP for prod,
// or "" to skip metrics entirely).
//
// Why OpenTelemetry over Prometheus or StatsD: push-model OTLP carries
// resource attributes (service.name, service.version, host) the collector
// can route on, so the same engine binary fans out cleanly when we go
// multi-host. No Prometheus server needed in the path; the collector
// can ship to Datadog, Honeycomb, Grafana Cloud, OpenObserve, anywhere
// that speaks OTLP.
package metrics

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Provider holds the meter provider so main can shut it down cleanly
// (Shutdown flushes pending batches).
type Provider struct {
	mp *sdkmetric.MeterProvider
}

func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || p.mp == nil {
		return nil
	}
	return p.mp.Shutdown(ctx)
}

// Counters / gauges / histograms exported for the engine's call sites.
// Nil-safe via the safe* helpers below: a nil instrument no-ops.
var (
	EventsTotal           metric.Int64Counter
	AlertsTotal           metric.Int64Counter
	GatewayTransitions    metric.Int64Counter
	BPFEntries            metric.Int64UpDownCounter
	BPFAttachedLinks      metric.Int64UpDownCounter
	TetragonConnected     metric.Int64UpDownCounter
	StoreInsertDuration   metric.Float64Histogram
	HTTPRequestDuration   metric.Float64Histogram
)

// Init wires up the global meter and creates every instrument. endpoint
// selects the exporter:
//
//	""        -> metrics disabled (instruments stay nil, calls no-op)
//	"stdout"  -> stdoutmetric exporter — every interval prints a JSON
//	             metric snapshot. Useful for dev / first-look.
//	"<other>" -> OTLP/HTTP exporter pointed at the given collector URL,
//	             e.g. "http://otel-collector:4318".
//
// hostname/version flow into resource attributes the collector can use
// for routing.
func Init(ctx context.Context, endpoint, hostname, version string) (*Provider, error) {
	if endpoint == "" {
		return &Provider{}, nil
	}

	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		semconv.ServiceName("ebpf-engine"),
		semconv.ServiceVersion(version),
		semconv.HostName(hostname),
	))
	if err != nil {
		return nil, fmt.Errorf("metrics: resource: %w", err)
	}

	var reader sdkmetric.Reader
	switch endpoint {
	case "stdout":
		exp, err := stdoutmetric.New()
		if err != nil {
			return nil, fmt.Errorf("metrics: stdout exporter: %w", err)
		}
		reader = sdkmetric.NewPeriodicReader(exp, sdkmetric.WithInterval(30*time.Second))
	default:
		// OTLP/HTTP. Treat the input as a base URL; the SDK appends
		// the canonical "/v1/metrics" path.
		opts := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpointURL(endpoint)}
		exp, err := otlpmetrichttp.New(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("metrics: otlp exporter: %w", err)
		}
		reader = sdkmetric.NewPeriodicReader(exp, sdkmetric.WithInterval(15*time.Second))
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(reader),
	)
	otel.SetMeterProvider(mp)

	m := mp.Meter("ebpf-engine")

	if EventsTotal, err = m.Int64Counter(
		"engine.events.total",
		metric.WithDescription("Tetragon events ingested by the engine, labeled by event type"),
	); err != nil {
		return nil, err
	}
	if AlertsTotal, err = m.Int64Counter(
		"engine.alerts.total",
		metric.WithDescription("Alerts emitted, labeled by severity"),
	); err != nil {
		return nil, err
	}
	if GatewayTransitions, err = m.Int64Counter(
		"engine.gateway.transitions",
		metric.WithDescription("Choke gateway state transitions, labeled by from/to state"),
	); err != nil {
		return nil, err
	}
	if BPFEntries, err = m.Int64UpDownCounter(
		"engine.bpf.entries",
		metric.WithDescription("Current BPF map size (entries in choke_pids)"),
	); err != nil {
		return nil, err
	}
	if BPFAttachedLinks, err = m.Int64UpDownCounter(
		"engine.bpf.attached_links",
		metric.WithDescription("Number of cgroup attach links the BPF program holds (4 expected)"),
	); err != nil {
		return nil, err
	}
	if TetragonConnected, err = m.Int64UpDownCounter(
		"engine.tetragon.connected",
		metric.WithDescription("1 when the Tetragon gRPC stream is healthy, 0 otherwise"),
	); err != nil {
		return nil, err
	}
	if StoreInsertDuration, err = m.Float64Histogram(
		"engine.store.insert.duration",
		metric.WithDescription("Time spent inserting a record into the events/alerts store"),
		metric.WithUnit("s"),
	); err != nil {
		return nil, err
	}
	if HTTPRequestDuration, err = m.Float64Histogram(
		"engine.http.request.duration",
		metric.WithDescription("HTTP request latency, labeled by path and status"),
		metric.WithUnit("s"),
	); err != nil {
		return nil, err
	}

	return &Provider{mp: mp}, nil
}

// Helpers below are nil-safe so call sites don't have to guard each call.

func IncEvent(eventType string) {
	if EventsTotal == nil {
		return
	}
	EventsTotal.Add(context.Background(), 1, metric.WithAttributes(attribute.String("type", eventType)))
}

func IncAlert(severity string) {
	if AlertsTotal == nil {
		return
	}
	AlertsTotal.Add(context.Background(), 1, metric.WithAttributes(attribute.String("severity", severity)))
}

func IncTransition(from, to string) {
	if GatewayTransitions == nil {
		return
	}
	GatewayTransitions.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("from", from),
		attribute.String("to", to),
	))
}

// gaugeState tracks the absolute value of an UpDownCounter-backed gauge
// so callers can pass "set to X" semantics; the helpers translate that
// into an Add(delta) call. UpDownCounter is intrinsically additive, so
// we own the running total to expose set-style helpers.
var (
	gaugeMu              sync.Mutex
	bpfEntriesValue      int64
	bpfLinksValue        int64
	tetragonConnVal      int64
)

// SetBPFEntries records the absolute count of entries currently in the
// BPF hash map. Computes the delta from the previous value internally.
func SetBPFEntries(value int64) {
	if BPFEntries == nil {
		return
	}
	gaugeMu.Lock()
	delta := value - bpfEntriesValue
	bpfEntriesValue = value
	gaugeMu.Unlock()
	if delta != 0 {
		BPFEntries.Add(context.Background(), delta)
	}
}

// SetBPFAttachedLinks records the absolute number of cgroup attach
// links the loader is holding (4 expected on full attach).
func SetBPFAttachedLinks(value int64) {
	if BPFAttachedLinks == nil {
		return
	}
	gaugeMu.Lock()
	delta := value - bpfLinksValue
	bpfLinksValue = value
	gaugeMu.Unlock()
	if delta != 0 {
		BPFAttachedLinks.Add(context.Background(), delta)
	}
}

// SetTetragonConnected records 1 (connected) or 0 (disconnected). Idempotent.
func SetTetragonConnected(connected bool) {
	if TetragonConnected == nil {
		return
	}
	target := int64(0)
	if connected {
		target = 1
	}
	gaugeMu.Lock()
	delta := target - tetragonConnVal
	tetragonConnVal = target
	gaugeMu.Unlock()
	if delta != 0 {
		TetragonConnected.Add(context.Background(), delta)
	}
}

func ObserveStoreInsert(seconds float64, kind string) {
	if StoreInsertDuration == nil {
		return
	}
	StoreInsertDuration.Record(context.Background(), seconds, metric.WithAttributes(attribute.String("kind", kind)))
}

func ObserveHTTPRequest(seconds float64, path, status string) {
	if HTTPRequestDuration == nil {
		return
	}
	HTTPRequestDuration.Record(context.Background(), seconds, metric.WithAttributes(
		attribute.String("path", path),
		attribute.String("status", status),
	))
}

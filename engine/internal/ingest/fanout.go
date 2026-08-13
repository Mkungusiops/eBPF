package ingest

// FanOut writes every record to a primary sink and mirrors it to zero or more
// secondary sinks. The primary is authoritative — its error is returned and
// fails the ingest. Secondaries are best-effort: a secondary failure is logged
// and swallowed, never propagated, so the events firehose (e.g. ClickHouse for
// retention/analytics) can never block ingest or drop a record from the primary
// store the operator reads from.
type FanOut struct {
	primary     Sink
	secondaries []Sink
	logf        func(string, ...any)
}

// NewFanOut builds a FanOut over a required primary and any number of best-effort
// secondaries. logf may be nil.
func NewFanOut(primary Sink, logf func(string, ...any), secondaries ...Sink) *FanOut {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &FanOut{primary: primary, secondaries: secondaries, logf: logf}
}

func (f *FanOut) Put(r StampedRecord) error {
	if err := f.primary.Put(r); err != nil {
		return err // authoritative store failed — surface it
	}
	for _, s := range f.secondaries {
		if err := s.Put(r); err != nil {
			f.logf("[ingest] firehose mirror failed (best-effort, record kept in primary): %v", err)
		}
	}
	return nil
}

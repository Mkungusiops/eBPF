package ingest

import (
	"errors"
	"testing"
)

type recSink struct {
	puts []StampedRecord
	err  error
}

func (r *recSink) Put(s StampedRecord) error {
	r.puts = append(r.puts, s)
	return r.err
}

func TestFanOutPrimaryErrorPropagatesAndSkipsMirror(t *testing.T) {
	primary := &recSink{err: errors.New("primary down")}
	sec := &recSink{}
	f := NewFanOut(primary, nil, sec)

	if err := f.Put(StampedRecord{TenantID: "t"}); err == nil {
		t.Fatal("primary error must propagate (ingest must fail)")
	}
	if len(sec.puts) != 0 {
		t.Fatal("secondary must not be written when the primary fails")
	}
}

func TestFanOutMirrorsAndSwallowsSecondaryError(t *testing.T) {
	primary := &recSink{}
	down := &recSink{err: errors.New("firehose down")}
	up := &recSink{}
	logged := 0
	f := NewFanOut(primary, func(string, ...any) { logged++ }, down, up)

	if err := f.Put(StampedRecord{TenantID: "t", AgentID: "a"}); err != nil {
		t.Fatalf("a secondary failure must not fail ingest, got %v", err)
	}
	if len(primary.puts) != 1 || len(down.puts) != 1 || len(up.puts) != 1 {
		t.Fatalf("every sink should receive the record: primary=%d down=%d up=%d",
			len(primary.puts), len(down.puts), len(up.puts))
	}
	if logged != 1 {
		t.Fatalf("expected exactly one logged mirror failure, got %d", logged)
	}
}

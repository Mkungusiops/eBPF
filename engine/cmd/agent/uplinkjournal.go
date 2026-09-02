package main

import (
	"github.com/jeffmk/ebpf-poc-engine/internal/store"
	"github.com/jeffmk/ebpf-poc-engine/internal/uplink"
)

// storeJournal makes the agent's local SQLite store satisfy uplink.Journal.
//
// The adapter lives here rather than in either package because uplink already
// imports store (for store.Event), so store implementing the interface
// directly would be an import cycle. cmd/agent imports both, and it is where
// the two are wired together anyway.
type storeJournal struct{ st *store.Store }

func (j storeJournal) Append(seq uint64, dedupKey string, payload []byte) error {
	return j.st.AppendUplink(seq, dedupKey, payload)
}

func (j storeJournal) DeleteThrough(seq uint64) error {
	return j.st.DeleteUplinkThrough(seq)
}

func (j storeJournal) Load() ([]uplink.JournalEntry, error) {
	rows, err := j.st.LoadUplink()
	if err != nil {
		return nil, err
	}
	out := make([]uplink.JournalEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, uplink.JournalEntry{Seq: r.Seq, Payload: r.Payload})
	}
	return out, nil
}

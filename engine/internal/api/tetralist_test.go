package api

import "testing"

// parseTetraList had no test at all, and the gap it left was not cosmetic: the
// parser returns an empty slice both when the kernel genuinely has no policies
// and when it could not make sense of the output. Callers read that as "every
// expected detection is missing" and reported a fabricated coverage gap as
// fact — on the sensor-health panel, whose only job is to say whether the
// platform can be trusted.

const realTable = `ID   NAME                    STATE     FILTERID   NAMESPACE   SENSORS         KERNELMEMORY   MODE      NPOST   NENFORCE   NMONITOR
1    outbound-connections    enabled   0          (global)    generic_kprobe  1.17 MB        monitor   12      0          0
2    sensitive-file-access   enabled   0          (global)    generic_kprobe  4.70 MB        monitor   1207    0          0`

func TestParseTetraListReadsARealTable(t *testing.T) {
	stats, recognised := parseTetraList(realTable)
	if !recognised {
		t.Fatal("a well-formed table must be recognised")
	}
	if len(stats) != 2 {
		t.Fatalf("got %d rows, want 2", len(stats))
	}
	if stats[0].Name != "outbound-connections" || stats[0].Mode != "monitor" || stats[0].State != "enabled" {
		t.Fatalf("first row parsed as %+v", stats[0])
	}
}

func TestAnEmptyKernelIsRecognisedAndEmpty(t *testing.T) {
	// Header, no rows. This genuinely means "no policies loaded", and the
	// caller is right to report a coverage gap.
	stats, recognised := parseTetraList("ID   NAME   STATE   MODE   NPOST")
	if !recognised {
		t.Fatal("a header with no rows is still a table we understood")
	}
	if len(stats) != 0 {
		t.Fatalf("got %d rows, want 0", len(stats))
	}
}

func TestUnrecognisedOutputIsNotAnEmptyKernel(t *testing.T) {
	// The bug. Each of these is something `tetra` or `docker` can print while
	// still exiting 0. Reporting them as "no policies loaded" tells an operator
	// their host is blind when it may be perfectly covered.
	for _, junk := range []string{
		"",
		"Error: failed to connect to tetragon",
		"WARNING: this command is deprecated",
		"unable to find image 'tetragon' locally",
		"{}",
	} {
		stats, recognised := parseTetraList(junk)
		if recognised {
			t.Errorf("output %q was treated as a policy table", junk)
		}
		if len(stats) != 0 {
			t.Errorf("output %q yielded %d rows", junk, len(stats))
		}
	}
}

// The gRPC read replaced a CLI scrape. It must not quietly return LESS than the
// scrape did, or a console field that used to be populated goes blank with no
// error anywhere — the kind of regression that is only noticed months later.
func TestHumanBytesMatchesTheCLIColumn(t *testing.T) {
	for _, c := range []struct {
		in   uint64
		want string
	}{
		{0, ""}, // the CLI omits it rather than printing "0 B"
		{512, "512 B"},
		{1024, "1.00 KB"},
		{4927115, "4.70 MB"}, // the value the live estate reports for sensitive-file-access
		{4479795, "4.27 MB"},
	} {
		if got := humanBytes(c.in); got != c.want {
			t.Errorf("humanBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

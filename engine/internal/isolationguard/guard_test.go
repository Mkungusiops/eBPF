package isolationguard

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	_ "github.com/jeffmk/ebpf-poc-engine/gen/ebpfsoc/v1" // register wire descriptors
	"github.com/jeffmk/ebpf-poc-engine/internal/authz"
)

func engineRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve source path")
	}
	// file = <engine>/internal/isolationguard/guard_test.go
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

var rawTelemetryQuery = regexp.MustCompile("(?i)(from|into|update|truncate)\\s+[\"'`]?telemetry\\b")

// TestNoRawTelemetryQueriesOutsideCentralStore is the Layer-3 bypass-lint: only
// internal/centralstore (the single tenant-scoped data-access layer) may run a
// raw query against the tenant-partitioned telemetry table. A raw query anywhere
// else could omit the tenant filter and leak.
func TestNoRawTelemetryQueriesOutsideCentralStore(t *testing.T) {
	root := engineRoot(t)
	var violations []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := d.Name()
			if base == "gen" || base == "centralstore" || base == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if rawTelemetryQuery.Match(data) {
			rel, _ := filepath.Rel(root, path)
			violations = append(violations, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) > 0 {
		t.Fatalf("raw telemetry-table queries outside internal/centralstore (Layer-3 bypass): %v", violations)
	}
}

// rpcPosture is the maintained isolation classification of every wire RPC.
// "tenant-scoped": tenant is derived from the mTLS cert and enforced.
// "bootstrap":     pre-identity (issues the cert); carries no tenant data.
// Adding an RPC to the proto without classifying it here fails the ratchet below.
var rpcPosture = map[string]string{
	"ebpfsoc.v1.EnrollmentService.Enroll":         "bootstrap",
	"ebpfsoc.v1.TelemetryService.StreamTelemetry": "tenant-scoped",
	"ebpfsoc.v1.CommandService.Commands":          "tenant-scoped",
	"ebpfsoc.v1.PolicyService.GetBundle":          "tenant-scoped",
	"ebpfsoc.v1.HeartbeatService.Heartbeat":       "tenant-scoped",
}

// TestEveryRPCHasIsolationPosture is the cross-tenant coverage RATCHET: every
// RPC in the wire contract must have a declared isolation posture, and the map
// must not name RPCs that no longer exist. A new endpoint therefore cannot ship
// without a conscious isolation decision.
func TestEveryRPCHasIsolationPosture(t *testing.T) {
	found := map[string]bool{}
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if fd.Package() != "ebpfsoc.v1" {
			return true
		}
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			svc := svcs.Get(i)
			methods := svc.Methods()
			for j := 0; j < methods.Len(); j++ {
				name := string(svc.FullName()) + "." + string(methods.Get(j).Name())
				found[name] = true
				if _, ok := rpcPosture[name]; !ok {
					t.Errorf("RPC %s has no isolation posture — classify it in rpcPosture (ratchet)", name)
				}
			}
		}
		return true
	})
	if len(found) == 0 {
		t.Fatal("no ebpfsoc.v1 RPCs discovered — descriptor registration failed")
	}
	for name := range rpcPosture {
		if !found[name] {
			t.Errorf("classified RPC %s no longer exists in the wire contract", name)
		}
	}
}

// TestDenialIsNotAnExistenceOracle: a denial for a tenant that "exists" and one
// for a tenant that does not must be indistinguishable — authz is purely
// grant-based and leaks no tenant-existence information (§6 side channels).
func TestDenialIsNotAnExistenceOracle(t *testing.T) {
	p := authz.Principal{Subject: "alice", Grants: []authz.Grant{{Role: authz.RoleTenantAnalyst, TenantID: "tenant-a"}}}
	d1 := authz.Authorize(p, "tenant-b", authz.ActionRead, nil)              // conceptually exists
	d2 := authz.Authorize(p, "tenant-does-not-exist", authz.ActionRead, nil) // does not
	if d1.Allowed || d2.Allowed {
		t.Fatal("both cross-tenant reads must be denied")
	}
	if d1.Reason != d2.Reason {
		t.Fatalf("denial reasons differ → existence oracle: %q vs %q", d1.Reason, d2.Reason)
	}
}

package tokens

import (
	"sync"
	"testing"
	"time"
)

func TestBucketBurstThenSteadyState(t *testing.T) {
	b := NewBucket(10, 5) // 10/sec, burst of 5
	for i := 0; i < 5; i++ {
		if !b.Allow() {
			t.Fatalf("burst token %d should pass", i)
		}
	}
	if b.Allow() {
		t.Fatalf("6th token should fail (burst exhausted)")
	}
	// Wait long enough to refill at least 1 token.
	time.Sleep(150 * time.Millisecond)
	if !b.Allow() {
		t.Fatalf("after refill window the bucket should allow at least one")
	}
}

func TestBucketCapsAtBurst(t *testing.T) {
	b := NewBucket(1000, 3)
	time.Sleep(50 * time.Millisecond) // would refill 50 tokens at 1000/s, but cap is 3
	for i := 0; i < 3; i++ {
		if !b.Allow() {
			t.Fatalf("token %d should pass", i)
		}
	}
	if b.Allow() {
		t.Fatalf("4th token should fail; refill must cap at burst")
	}
}

func TestManagerFailOpenWhenNoBucket(t *testing.T) {
	m := NewManager()
	if !m.Allow(Key{PID: 1, Dimension: "x"}) {
		t.Fatalf("manager must fail-open when no bucket is installed")
	}
}

func TestManagerInstallReplacesBucket(t *testing.T) {
	m := NewManager()
	k := Key{PID: 1, Dimension: "egress"}
	m.Install(k, 1, 1)
	if !m.Allow(k) {
		t.Fatal("first allow should pass")
	}
	if m.Allow(k) {
		t.Fatal("second allow should fail (burst=1 exhausted)")
	}
	// Replace with a permissive bucket — must take effect immediately.
	m.Install(k, 1000, 100)
	if !m.Allow(k) {
		t.Fatal("after re-install, allow should pass with new rate")
	}
}

func TestManagerForgetPID(t *testing.T) {
	m := NewManager()
	m.Install(Key{PID: 1, Dimension: "a"}, 1, 1)
	m.Install(Key{PID: 1, Dimension: "b"}, 1, 1)
	m.Install(Key{PID: 2, Dimension: "a"}, 1, 1)
	if m.Tracked() != 3 {
		t.Fatalf("tracked=%d want 3", m.Tracked())
	}
	m.ForgetPID(1)
	if m.Tracked() != 1 {
		t.Fatalf("tracked=%d want 1 after forget", m.Tracked())
	}
}

func TestManagerConcurrent(t *testing.T) {
	m := NewManager()
	k := Key{PID: 1, Dimension: "x"}
	m.Install(k, 1e9, 1e9) // effectively unlimited
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				m.Allow(k)
			}
		}()
	}
	wg.Wait()
}

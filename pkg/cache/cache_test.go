package cache

import (
	"testing"
	"time"
)

func TestGetDeletesExpired(t *testing.T) {
	c := NewCache("t")
	c.Set("k", "v", time.Millisecond)
	time.Sleep(2 * time.Millisecond)
	if _, ok := c.Get("k"); ok {
		t.Fatal("expected miss")
	}
	if c.Size() != 0 {
		t.Fatalf("size=%d", c.Size())
	}
}

func TestSetZeroTTLRemoves(t *testing.T) {
	c := NewCache("t")
	c.Set("k", "v", time.Hour)
	c.Set("k", "v", 0)
	if _, ok := c.Get("k"); ok {
		t.Fatal("expected removed")
	}
}

func TestSweep(t *testing.T) {
	c := NewCache("t")
	c.Set("live", 1, time.Hour)
	c.Set("dead", 2, time.Millisecond)
	time.Sleep(2 * time.Millisecond)
	if n := c.Sweep(); n != 1 {
		t.Fatalf("swept %d", n)
	}
	if c.Size() != 1 {
		t.Fatalf("size=%d", c.Size())
	}
}

func TestMaxEntriesEvictsSoonestExpiry(t *testing.T) {
	c := NewLimitedCache("t", 2)
	c.Set("a", 1, time.Hour)
	c.Set("b", 2, 2*time.Hour)
	c.Set("c", 3, 3*time.Hour)
	if c.Size() != 2 {
		t.Fatalf("size=%d", c.Size())
	}
	if _, ok := c.Get("a"); ok {
		t.Fatal("soonest expiry should have been evicted")
	}
}

func TestRemoveExactOrPrefixed(t *testing.T) {
	c := NewCache("t")
	c.Set("https://e", 1, time.Hour)
	c.Set("https://e:https://ta", 2, time.Hour)
	c.Set("https://e-other", 3, time.Hour)
	n := c.RemoveExactOrPrefixed("https://e")
	if n != 2 {
		t.Fatalf("removed %d", n)
	}
	if _, ok := c.Get("https://e-other"); !ok {
		t.Fatal("unrelated key removed")
	}
}

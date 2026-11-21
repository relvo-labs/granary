// Copyright (c) 2015-2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package ldap

import (
	"fmt"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time          { return f.t }
func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }

func newTestLimiter(cfg LoginLimitConfig) (*LoginFailureLimiter, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l := NewLoginFailureLimiter(cfg)
	if l != nil {
		l.now = clk.now
	}
	return l, clk
}

// fail runs one complete failed attempt and reports whether it was allowed.
func fail(l *LoginFailureLimiter, user, ip string) bool {
	if !l.Reserve(user, ip) {
		return false
	}
	l.Finish(user, ip, true)
	return true
}

// succeed runs one complete successful attempt and reports whether it was
// allowed.
func succeed(l *LoginFailureLimiter, user, ip string) bool {
	if !l.Reserve(user, ip) {
		return false
	}
	l.Finish(user, ip, false)
	return true
}

func TestLoginFailureLimiterUserLimit(t *testing.T) {
	l, _ := newTestLimiter(LoginLimitConfig{UserLimit: 3, IPLimit: 100, Window: time.Minute})
	for i := range 3 {
		if !fail(l, "alice", "10.0.0.1") {
			t.Fatalf("attempt %d unexpectedly throttled", i+1)
		}
	}
	if succeed(l, "alice", "10.0.0.1") {
		t.Fatal("expected alice to be throttled after 3 failures, even with a correct password")
	}
	// The per-user limit follows the account across source addresses.
	if succeed(l, "alice", "10.0.0.2") {
		t.Fatal("expected alice to be throttled from another address")
	}
	// Case and surrounding space variations share the same budget.
	if succeed(l, " ALICE ", "10.0.0.2") {
		t.Fatal("expected a case variant of alice to be throttled")
	}
	// Other accounts are unaffected.
	if !succeed(l, "bob", "10.0.0.1") {
		t.Fatal("bob must not be throttled by alice's failures")
	}
}

func TestLoginFailureLimiterIPLimit(t *testing.T) {
	l, _ := newTestLimiter(LoginLimitConfig{UserLimit: 100, IPLimit: 4, Window: time.Minute})
	for i := range 4 {
		if !fail(l, fmt.Sprintf("user%d", i), "192.0.2.1") {
			t.Fatalf("attempt %d unexpectedly throttled", i+1)
		}
	}
	if succeed(l, "fresh-user", "192.0.2.1") {
		t.Fatal("expected source IP to be throttled after 4 failures")
	}
	if !succeed(l, "fresh-user", "192.0.2.2") {
		t.Fatal("another source IP must not be throttled")
	}
}

func TestLoginFailureLimiterExpiry(t *testing.T) {
	l, clk := newTestLimiter(LoginLimitConfig{UserLimit: 2, IPLimit: 2, Window: time.Minute})
	fail(l, "alice", "10.0.0.1")
	fail(l, "alice", "10.0.0.1")
	if succeed(l, "alice", "10.0.0.1") {
		t.Fatal("expected throttling")
	}
	clk.advance(59 * time.Second)
	if succeed(l, "alice", "10.0.0.1") {
		t.Fatal("expected throttling until the window ends")
	}
	clk.advance(time.Second)
	if !succeed(l, "alice", "10.0.0.1") {
		t.Fatal("expected throttling to end after the window")
	}
	// A new window starts with a fresh budget.
	if !fail(l, "alice", "10.0.0.1") || !succeed(l, "alice", "10.0.0.1") {
		t.Fatal("one failure in a new window must not throttle")
	}
}

func TestLoginFailureLimiterOnlyFailuresCount(t *testing.T) {
	l, _ := newTestLimiter(LoginLimitConfig{UserLimit: 2, IPLimit: 2, Window: time.Minute})
	for i := range 100 {
		if !succeed(l, "alice", "10.0.0.1") {
			t.Fatalf("successful attempt %d was throttled", i+1)
		}
	}
	if u, ip := l.tracked(); u != 0 || ip != 0 {
		t.Fatalf("successful attempts left state behind: %d users, %d ips", u, ip)
	}
	// Successes in between do not reset the failure count either.
	fail(l, "alice", "10.0.0.1")
	succeed(l, "alice", "10.0.0.1")
	fail(l, "alice", "10.0.0.1")
	if succeed(l, "alice", "10.0.0.1") {
		t.Fatal("expected throttling after 2 failures")
	}
}

func TestLoginFailureLimiterConcurrentBurst(t *testing.T) {
	l, _ := newTestLimiter(LoginLimitConfig{UserLimit: 3, IPLimit: 100, Window: time.Minute})
	// Attempts still in flight count against the limit, so a burst of
	// concurrent guesses cannot exceed the failure budget.
	admitted := 0
	for range 50 {
		if l.Reserve("alice", "10.0.0.1") {
			admitted++
		}
	}
	if admitted != 3 {
		t.Fatalf("expected 3 concurrent attempts to be admitted, got %d", admitted)
	}
	for range admitted {
		l.Finish("alice", "10.0.0.1", false)
	}
	if !succeed(l, "alice", "10.0.0.1") {
		t.Fatal("released reservations must not throttle")
	}
	if u, ip := l.tracked(); u != 0 || ip != 0 {
		t.Fatalf("released reservations left state behind: %d users, %d ips", u, ip)
	}
}

func TestLoginFailureLimiterBounded(t *testing.T) {
	const maxEntries = 50
	l, clk := newTestLimiter(LoginLimitConfig{UserLimit: 5, IPLimit: 5, Window: time.Minute, MaxEntries: maxEntries})
	for i := range 10 * maxEntries {
		fail(l, fmt.Sprintf("user-%d", i), fmt.Sprintf("198.51.100.%d", i))
		clk.advance(time.Millisecond)
		if u, ip := l.tracked(); u > maxEntries || ip > maxEntries {
			t.Fatalf("tables exceed bound: %d users, %d ips", u, ip)
		}
	}
	if u, ip := l.tracked(); u != maxEntries || ip != maxEntries {
		t.Fatalf("expected full tables, got %d users, %d ips", u, ip)
	}
	// The most recent key is still tracked after eviction.
	last := fmt.Sprintf("user-%d", 10*maxEntries-1)
	for range 4 {
		fail(l, last, "203.0.113.1")
	}
	if succeed(l, last, "203.0.113.9") {
		t.Fatal("expected the most recent key to remain tracked")
	}
	// Expired entries are reclaimed before live ones are evicted.
	clk.advance(time.Minute)
	fail(l, "after-expiry", "203.0.113.2")
	if u, _ := l.tracked(); u != 1 {
		t.Fatalf("expected expired entries to be pruned, %d users tracked", u)
	}
}

func TestLoginFailureLimiterDisabled(t *testing.T) {
	l := NewLoginFailureLimiter(LoginLimitConfig{})
	if l != nil {
		t.Fatal("expected nil limiter when both limits are disabled")
	}
	for range 100 {
		if !fail(l, "alice", "10.0.0.1") {
			t.Fatal("a nil limiter must allow everything")
		}
	}

	// Disabling a single dimension leaves the other in force.
	l, _ = newTestLimiter(LoginLimitConfig{UserLimit: 0, IPLimit: 2, Window: time.Minute})
	fail(l, "alice", "10.0.0.1")
	fail(l, "bob", "10.0.0.1")
	if succeed(l, "carol", "10.0.0.1") {
		t.Fatal("expected IP throttling with the user limit disabled")
	}
	if !succeed(l, "alice", "10.0.0.2") {
		t.Fatal("user limit is disabled; alice must be allowed elsewhere")
	}
}

func TestLookupLoginLimitConfig(t *testing.T) {
	lookup := func(vals map[string]string) (LoginLimitConfig, error) {
		return lookupLoginLimitConfig(func(k string) string { return vals[k] })
	}

	cfg, err := lookup(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := LoginLimitConfig{
		UserLimit:  DefaultLoginFailureUserLimit,
		IPLimit:    DefaultLoginFailureIPLimit,
		Window:     DefaultLoginFailureWindow,
		MaxEntries: DefaultLoginFailureMaxEntries,
	}
	if cfg != want {
		t.Fatalf("defaults: got %+v, want %+v", cfg, want)
	}

	cfg, err = lookup(map[string]string{
		LoginFailureUserLimit: "5",
		LoginFailureIPLimit:   "0",
		LoginFailureWindow:    "1h",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UserLimit != 5 || cfg.IPLimit != 0 || cfg.Window != time.Hour {
		t.Fatalf("unexpected parsed config %+v", cfg)
	}

	for _, bad := range []map[string]string{
		{LoginFailureUserLimit: "-1"},
		{LoginFailureIPLimit: "many"},
		{LoginFailureWindow: "0s"},
		{LoginFailureWindow: "soon"},
	} {
		if _, err := lookup(bad); err == nil {
			t.Fatalf("expected error for %v", bad)
		}
	}
}

func TestLoginLimitKeysDocumented(t *testing.T) {
	for _, key := range []string{LoginFailureUserLimit, LoginFailureIPLimit, LoginFailureWindow} {
		if _, ok := DefaultKVS.Lookup(key); !ok {
			t.Errorf("%s missing from DefaultKVS", key)
		}
		if _, ok := Help.Lookup(key); !ok {
			t.Errorf("%s missing from Help", key)
		}
	}
}

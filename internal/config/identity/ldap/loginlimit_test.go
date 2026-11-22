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
	"errors"
	"fmt"
	"strings"
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
	a, ok := l.Reserve(user, ip)
	if !ok {
		return false
	}
	a.Finish(true)
	return true
}

// succeed runs one complete successful attempt and reports whether it was
// allowed.
func succeed(l *LoginFailureLimiter, user, ip string) bool {
	a, ok := l.Reserve(user, ip)
	if !ok {
		return false
	}
	a.Finish(false)
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
	var admitted []*LoginAttempt
	for range 50 {
		if a, ok := l.Reserve("alice", "10.0.0.1"); ok {
			admitted = append(admitted, a)
		}
	}
	if len(admitted) != 3 {
		t.Fatalf("expected 3 concurrent attempts to be admitted, got %d", len(admitted))
	}
	for _, a := range admitted {
		a.Finish(false)
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
	refused := 0
	for i := range 10 * maxEntries {
		if !fail(l, fmt.Sprintf("user-%d", i), fmt.Sprintf("198.51.100.%d", i)) {
			refused++
		}
		clk.advance(time.Millisecond)
		if u, ip := l.tracked(); u > maxEntries || ip > maxEntries {
			t.Fatalf("tables exceed bound: %d users, %d ips", u, ip)
		}
	}
	if u, ip := l.tracked(); u != maxEntries || ip != maxEntries {
		t.Fatalf("expected full tables, got %d users, %d ips", u, ip)
	}
	// Keys beyond the capacity are refused rather than evicting live ones.
	if refused != 9*maxEntries {
		t.Fatalf("expected %d new keys to be refused while full, got %d", 9*maxEntries, refused)
	}
	// Keys that are already tracked keep working while the table is full.
	if !fail(l, "user-0", "198.51.100.0") {
		t.Fatal("a tracked key must not be refused because the table is full")
	}
	// Expired entries are reclaimed once their window ends.
	clk.advance(time.Minute)
	if !fail(l, "after-expiry", "203.0.113.2") {
		t.Fatal("expected a new key to be admitted after the entries expired")
	}
	if u, _ := l.tracked(); u != 1 {
		t.Fatalf("expected expired entries to be pruned, %d users tracked", u)
	}
}

// A full table refuses new keys cheaply until the first entry can expire,
// and admits them again as soon as an in-flight slot is freed.
func TestLoginFailureLimiterFullTableRecovery(t *testing.T) {
	l, clk := newTestLimiter(LoginLimitConfig{UserLimit: 5, IPLimit: 0, Window: time.Minute, MaxEntries: 2})
	fail(l, "alice", "")
	clk.advance(10 * time.Second)
	pending, ok := l.Reserve("bob", "")
	if !ok {
		t.Fatal("bob refused")
	}
	if succeed(l, "carol", "") {
		t.Fatal("expected carol to be refused while the table is full")
	}
	// bob's attempt finishes successfully and frees its slot.
	pending.Finish(false)
	if !succeed(l, "carol", "") {
		t.Fatal("expected carol to be admitted after bob's slot was freed")
	}
	fail(l, "dave", "")
	if succeed(l, "erin", "") {
		t.Fatal("expected erin to be refused while the table is full")
	}
	// alice's window ends first and frees a slot.
	clk.advance(50 * time.Second)
	if !succeed(l, "erin", "") {
		t.Fatal("expected erin to be admitted once alice's window ended")
	}
}

// Finish and Abort complete an attempt exactly once.
func TestLoginAttemptExactlyOnce(t *testing.T) {
	l, _ := newTestLimiter(LoginLimitConfig{UserLimit: 2, IPLimit: 2, Window: time.Minute})
	a, ok := l.Reserve("alice", "10.0.0.1")
	if !ok {
		t.Fatal("refused")
	}
	a.Finish(true)
	a.Abort()
	a.Finish(true)
	if u, ip := l.pending(); u != 0 || ip != 0 {
		t.Fatalf("pending reservations left: %d users, %d ips", u, ip)
	}
	// Only one failure was counted.
	if !fail(l, "alice", "10.0.0.1") {
		t.Fatal("a repeated completion was counted as another failure")
	}
	if succeed(l, "alice", "10.0.0.1") {
		t.Fatal("expected throttling after two failures")
	}
	// Abort without Finish releases the reservation without counting.
	b, ok := l.Reserve("bob", "10.0.0.2")
	if !ok {
		t.Fatal("refused")
	}
	b.Abort()
	if u, ip := l.tracked(); u != 1 || ip != 1 {
		t.Fatalf("aborted attempt left state behind: %d users, %d ips", u, ip)
	}
	// A nil attempt, as returned by a disabled limiter, is a no-op.
	var none *LoginAttempt
	none.Finish(true)
	none.Abort()
}

func TestLoginCredentialLengthLimits(t *testing.T) {
	for _, c := range []struct {
		user, pass string
		ok         bool
	}{
		{"alice", "secret", true},
		{strings.Repeat("u", MaxLoginUsernameLength), strings.Repeat("p", MaxLoginPasswordLength), true},
		{strings.Repeat("u", MaxLoginUsernameLength+1), "secret", false},
		{"alice", strings.Repeat("p", MaxLoginPasswordLength+1), false},
	} {
		if got := ValidLoginCredentialLengths(c.user, c.pass); got != c.ok {
			t.Errorf("lengths %d/%d: got %v, want %v", len(c.user), len(c.pass), got, c.ok)
		}
	}
	// Bind enforces the same limit for its other callers.
	var cfg Config
	if _, _, err := cfg.Bind(strings.Repeat("u", MaxLoginUsernameLength+1), "secret"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected Bind to reject an over-long username as invalid credentials, got %v", err)
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

		MinResponseTime: DefaultLoginFailureMinResponseTime,
	}
	if cfg != want {
		t.Fatalf("defaults: got %+v, want %+v", cfg, want)
	}

	cfg, err = lookup(map[string]string{
		LoginFailureUserLimit: "5",
		LoginFailureIPLimit:   "0",
		LoginFailureWindow:    "1h",

		LoginFailureMinResponseTime: "250ms",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UserLimit != 5 || cfg.IPLimit != 0 || cfg.Window != time.Hour || cfg.MinResponseTime != 250*time.Millisecond {
		t.Fatalf("unexpected parsed config %+v", cfg)
	}

	for _, bad := range []map[string]string{
		{LoginFailureUserLimit: "-1"},
		{LoginFailureIPLimit: "many"},
		{LoginFailureWindow: "0s"},
		{LoginFailureWindow: "soon"},
		{LoginFailureMinResponseTime: "-1s"},
		{LoginFailureMinResponseTime: "31s"},
		{LoginFailureMinResponseTime: "later"},
	} {
		if _, err := lookup(bad); err == nil {
			t.Fatalf("expected error for %v", bad)
		}
	}
}

func TestLoginLimitKeysDocumented(t *testing.T) {
	for _, key := range []string{LoginFailureUserLimit, LoginFailureIPLimit, LoginFailureWindow, LoginFailureMinResponseTime} {
		if _, ok := DefaultKVS.Lookup(key); !ok {
			t.Errorf("%s missing from DefaultKVS", key)
		}
		if _, ok := Help.Lookup(key); !ok {
			t.Errorf("%s missing from Help", key)
		}
	}
}

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
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// Regression tests for the failed-login protections. They only use the
// helpers in loginlimit_adapter_test.go.

// A full table must not forget a throttled key to make room for a new one;
// the new key is refused instead.
func TestLoginFailureLimiterFullTableKeepsThrottledKeys(t *testing.T) {
	l, clk := newTestLimiter(LoginLimitConfig{UserLimit: 2, IPLimit: 100, Window: time.Minute, MaxEntries: 2})
	for range 2 {
		finish, ok := testReserve(l, "alice", "10.0.0.1")
		if !ok {
			t.Fatal("alice unexpectedly throttled")
		}
		finish(true)
		clk.advance(time.Second)
	}
	finish, ok := testReserve(l, "bob", "10.0.0.1")
	if !ok {
		t.Fatal("bob unexpectedly refused")
	}
	finish(true)

	// The user table is full of live counters.
	if finish, ok := testReserve(l, "carol", "10.0.0.1"); ok {
		finish(true)
		t.Error("a new username was admitted although the table is full of live entries")
	}
	if finish, ok := testReserve(l, "alice", "10.0.0.1"); ok {
		finish(false)
		t.Fatal("alice's failures were evicted: throttled account admitted again")
	}

	// Once the window has passed, the slots are reclaimed.
	clk.advance(time.Minute)
	finish, ok = testReserve(l, "carol", "10.0.0.1")
	if !ok {
		t.Fatal("expected a new username to be admitted after the entries expired")
	}
	finish(false)
}

// A full table must not drop an attempt that is still in flight.
func TestLoginFailureLimiterFullTableKeepsReservations(t *testing.T) {
	l, _ := newTestLimiter(LoginLimitConfig{UserLimit: 1, IPLimit: 100, Window: time.Minute, MaxEntries: 1})
	finishA, ok := testReserve(l, "alice", "10.0.0.1")
	if !ok {
		t.Fatal("first attempt refused")
	}
	if finish, ok := testReserve(l, "bob", "10.0.0.1"); ok {
		finish(false)
		t.Error("a new username was admitted by dropping an in-flight reservation")
	}
	if finish, ok := testReserve(l, "alice", "10.0.0.1"); ok {
		finish(false)
		t.Fatal("a second concurrent attempt for alice was admitted beyond the limit of 1")
	}
	finishA(false)
	finish, ok := testReserve(l, "bob", "10.0.0.1")
	if !ok {
		t.Fatal("expected bob to be admitted once alice's attempt finished")
	}
	finish(false)
}

// Completing an attempt must only release its own reservation, even if it
// is completed more than once.
func TestLoginAttemptCompletesOnlyItsReservation(t *testing.T) {
	l, _ := newTestLimiter(LoginLimitConfig{UserLimit: 1, IPLimit: 100, Window: time.Minute})
	finishA, ok := testReserve(l, "alice", "10.0.0.1")
	if !ok {
		t.Fatal("first attempt refused")
	}
	finishA(false)
	finishB, ok := testReserve(l, "alice", "10.0.0.1")
	if !ok {
		t.Fatal("second attempt refused")
	}
	finishA(false) // duplicate completion of the first attempt
	if finish, ok := testReserve(l, "alice", "10.0.0.1"); ok {
		finish(false)
		t.Fatal("completing an old attempt released another attempt's reservation")
	}
	finishB(false)
}

// The limiter must hold a fixed amount of memory per key, however long the
// submitted username or address is.
func TestLoginFailureLimiterStoresFixedSizeKeys(t *testing.T) {
	l, _ := newTestLimiter(LoginLimitConfig{UserLimit: 5, IPLimit: 5, Window: time.Minute})
	user := strings.Repeat("u", 1<<20)
	ip := strings.Repeat("9", 64<<10)
	finish, ok := testReserve(l, user, ip)
	if !ok {
		t.Fatal("attempt refused")
	}
	finish(true)
	if n := retainedKeyBytes(l); n > 2*64 {
		t.Fatalf("limiter retains %d key bytes for one username and one address", n)
	}
}

// Over-long credentials are rejected like any invalid credentials, without
// contacting the directory.
func TestLoginRejectsOverlongCredentials(t *testing.T) {
	d := newFakeDirectory(t, 0)
	d.addUser("alice", fakeUser{password: "alice-pass"})
	cfg := d.config(t)
	l, _ := newTestLimiter(LoginLimitConfig{UserLimit: 5, IPLimit: 5, Window: time.Minute})
	setLoginLimiter(cfg, l)

	before := d.conns.Load()
	for _, c := range []struct{ user, pass string }{
		{strings.Repeat("a", 1<<20), "alice-pass"},
		{"alice", strings.Repeat("p", 1<<20)},
	} {
		err := testLogin(context.Background(), cfg, c.user, c.pass, "10.0.0.1")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("expected invalid credentials for over-long input, got %v", err)
		}
	}
	if n := d.conns.Load() - before; n != 0 {
		t.Fatalf("over-long credentials reached the directory (%d connections)", n)
	}
	if n := retainedKeyBytes(l); n > 2*64 {
		t.Fatalf("over-long credentials left %d key bytes in the limiter", n)
	}
}

// With a directory whose password hash is expensive, unknown accounts are
// rejected much faster than wrong passwords. Every rejection must take at
// least the minimum response time.
func TestLoginSlowHashDirectoryRejectionTiming(t *testing.T) {
	const (
		passwordCost = 150 * time.Millisecond
		minResponse  = 400 * time.Millisecond
	)
	d := newFakeDirectory(t, passwordCost)
	d.addUser("alice", fakeUser{password: "alice-pass"})
	d.addUser("dora", fakeUser{password: "dora-pass", disabled: true})
	cfg := d.config(t)
	setLoginMinResponseTime(cfg, minResponse)

	for _, c := range []struct{ name, user, pass string }{
		{"unknown account", "nosuchuser", "guess"},
		{"wrong password", "alice", "guess"},
		{"disabled account", "dora", "dora-pass"},
	} {
		start := time.Now()
		err := testLogin(context.Background(), cfg, c.user, c.pass, "10.0.0.1")
		took := time.Since(start)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("%s: expected invalid credentials, got %v", c.name, err)
		}
		if took < minResponse {
			t.Errorf("%s: rejected after %v, before the minimum response time %v", c.name, took, minResponse)
		}
	}
	if err := testLogin(context.Background(), cfg, "alice", "alice-pass", "10.0.0.1"); err != nil {
		t.Fatalf("expected a successful login, got %v", err)
	}
}

// Directory errors during the user search are not credential failures:
// they are not reported as such and not counted.
func TestLoginLookupErrorsAreNotCredentialFailures(t *testing.T) {
	d := newFakeDirectory(t, 0)
	cfg := d.config(t)
	l, _ := newTestLimiter(LoginLimitConfig{UserLimit: 1, IPLimit: 100, Window: time.Minute})
	setLoginLimiter(cfg, l)
	for _, code := range []uint16{
		ldap.LDAPResultInsufficientAccessRights,
		ldap.LDAPResultConfidentialityRequired,
		ldap.LDAPResultProtocolError,
		ldap.LDAPResultSizeLimitExceeded,
	} {
		d.failSearch("carol", code)
		for range 2 {
			err := testLogin(context.Background(), cfg, "carol", "guess", "10.0.0.1")
			if err == nil {
				t.Fatalf("code %d: expected an error", code)
			}
			if errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("code %d: directory error reported as invalid credentials: %v", code, err)
			}
		}
	}
	// No failure was counted, so carol can still try.
	finish, ok := testReserve(l, "carol", "10.0.0.1")
	if !ok {
		t.Fatal("directory errors were counted as failed logins")
	}
	finish(false)
}

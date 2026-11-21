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
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	xldap "github.com/minio/pkg/v3/ldap"
)

// recordingFloor is a minimum response time with a controllable clock that
// records the waits requested instead of sleeping.
type recordingFloor struct {
	mu    sync.Mutex
	clk   *fakeClock
	waits []time.Duration
	hook  func() // runs inside the wait, if set
}

func (r *recordingFloor) install(cfg *Config, minDuration time.Duration) {
	cfg.loginFloor = &loginResponseFloor{
		min: minDuration,
		now: func() time.Time {
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.clk.now()
		},
		sleep: func(d time.Duration) {
			r.mu.Lock()
			r.waits = append(r.waits, d)
			hook := r.hook
			r.mu.Unlock()
			if hook != nil {
				hook()
			}
		},
	}
}

func (r *recordingFloor) take() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	w := r.waits
	r.waits = nil
	return w
}

func TestLoginMinResponseTimeDeterministic(t *testing.T) {
	const minResponse = time.Second
	d := newFakeDirectory(t, 0)
	d.addUser("alice", fakeUser{password: "alice-pass"})
	d.addUser("dora", fakeUser{password: "dora-pass", disabled: true})
	d.failSearch("broken", ldap.LDAPResultInsufficientAccessRights)
	cfg := d.config(t)
	rec := &recordingFloor{clk: &fakeClock{t: time.Unix(1_700_000_000, 0)}}
	rec.install(cfg, minResponse)
	ctx := context.Background()

	// Every rejection waits for the full minimum (the fake clock does not
	// advance while the directory is queried).
	for _, c := range []struct{ name, user, pass string }{
		{"unknown account", "nosuchuser", "guess"},
		{"wrong password", "alice", "guess"},
		{"disabled account", "dora", "dora-pass"},
		{"over-long username", strings.Repeat("a", MaxLoginUsernameLength+1), "guess"},
		{"over-long password", "alice", strings.Repeat("p", MaxLoginPasswordLength+1)},
	} {
		_, _, err := cfg.Login(ctx, c.user, c.pass, "10.0.0.1")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("%s: expected invalid credentials, got %v", c.name, err)
		}
		if w := rec.take(); len(w) != 1 || w[0] != minResponse {
			t.Fatalf("%s: expected one wait of %v, got %v", c.name, minResponse, w)
		}
	}

	// Success and directory errors are not delayed.
	if _, _, err := cfg.Login(ctx, "alice", "alice-pass", "10.0.0.1"); err != nil {
		t.Fatalf("expected a successful login, got %v", err)
	}
	if w := rec.take(); len(w) != 0 {
		t.Fatalf("successful login was delayed: %v", w)
	}
	if _, _, err := cfg.Login(ctx, "broken", "guess", "10.0.0.1"); err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected a directory error, got %v", err)
	}
	if w := rec.take(); len(w) != 0 {
		t.Fatalf("directory error was delayed: %v", w)
	}

	// Time already spent counts towards the minimum.
	cfg.bindFn = func(username, password string) (*xldap.DNSearchResult, []string, error) {
		rec.mu.Lock()
		rec.clk.advance(300 * time.Millisecond)
		rec.mu.Unlock()
		return nil, nil, ErrInvalidCredentials
	}
	_, _, _ = cfg.Login(ctx, "alice", "guess", "10.0.0.1")
	if w := rec.take(); len(w) != 1 || w[0] != 700*time.Millisecond {
		t.Fatalf("expected a wait of 700ms after 300ms of work, got %v", w)
	}
	// Work longer than the minimum is not delayed further.
	cfg.bindFn = func(username, password string) (*xldap.DNSearchResult, []string, error) {
		rec.mu.Lock()
		rec.clk.advance(2 * time.Second)
		rec.mu.Unlock()
		return nil, nil, ErrInvalidCredentials
	}
	_, _, _ = cfg.Login(ctx, "alice", "guess", "10.0.0.1")
	if w := rec.take(); len(w) != 0 {
		t.Fatalf("expected no wait after 2s of work, got %v", w)
	}

	// Throttled attempts are refused immediately, without the delay.
	cfg.bindFn = nil
	l, _ := newTestLimiter(LoginLimitConfig{UserLimit: 1, IPLimit: 100, Window: time.Minute})
	setLoginLimiter(cfg, l)
	_, _, _ = cfg.Login(ctx, "alice", "guess", "10.0.0.1")
	rec.take()
	if _, _, err := cfg.Login(ctx, "alice", "alice-pass", "10.0.0.1"); !errors.Is(err, ErrLoginThrottled) {
		t.Fatalf("expected throttling, got %v", err)
	}
	if w := rec.take(); len(w) != 0 {
		t.Fatalf("throttled login was delayed: %v", w)
	}

	// Disabled by default when unset (zero).
	setLoginMinResponseTime(cfg, 0)
	if cfg.loginFloor != nil {
		t.Fatal("expected a zero minimum response time to disable the delay")
	}
}

// The wait happens after the limiter is updated and without its lock, so
// that other logins are not blocked while a rejection is delayed.
func TestLoginMinResponseTimeDoesNotHoldLimiter(t *testing.T) {
	d := newFakeDirectory(t, 0)
	cfg := d.config(t)
	l, _ := newTestLimiter(LoginLimitConfig{UserLimit: 5, IPLimit: 100, Window: time.Minute})
	setLoginLimiter(cfg, l)
	rec := &recordingFloor{clk: &fakeClock{t: time.Unix(1_700_000_000, 0)}}
	var pendingDuringWait [2]int
	rec.hook = func() {
		done := make(chan struct{})
		go func() {
			defer close(done)
			pendingDuringWait[0], pendingDuringWait[1] = l.pending()
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("limiter lock is held during the minimum response time wait")
		}
	}
	rec.install(cfg, time.Second)
	if _, _, err := cfg.Login(context.Background(), "nosuchuser", "guess", "10.0.0.1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
	if pendingDuringWait != [2]int{0, 0} {
		t.Fatalf("reservation still held during the wait: %v", pendingDuringWait)
	}
}

// The wait never exceeds the minimum response time, even if the clock
// moves backwards while the directory is queried.
func TestLoginMinResponseTimeBounded(t *testing.T) {
	var cfg Config
	rec := &recordingFloor{clk: &fakeClock{t: time.Unix(1_700_000_000, 0)}}
	rec.install(&cfg, time.Second)
	cfg.bindFn = func(username, password string) (*xldap.DNSearchResult, []string, error) {
		rec.mu.Lock()
		rec.clk.advance(-time.Hour)
		rec.mu.Unlock()
		return nil, nil, ErrInvalidCredentials
	}
	_, _, _ = cfg.Login(context.Background(), "alice", "guess", "10.0.0.1")
	if w := rec.take(); len(w) != 1 || w[0] != time.Second {
		t.Fatalf("expected one wait of at most 1s, got %v", w)
	}
}

// A panic while talking to the directory must not leak the reservation.
func TestLoginReleasesReservationOnPanic(t *testing.T) {
	var cfg Config
	l, _ := newTestLimiter(LoginLimitConfig{UserLimit: 1, IPLimit: 1, Window: time.Minute})
	setLoginLimiter(&cfg, l)
	cfg.bindFn = func(username, password string) (*xldap.DNSearchResult, []string, error) {
		panic("directory client bug")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected the panic to propagate")
			}
		}()
		_, _, _ = cfg.Login(context.Background(), "alice", "guess", "10.0.0.1")
	}()
	if u, ip := l.pending(); u != 0 || ip != 0 {
		t.Fatalf("panic leaked reservations: %d users, %d ips", u, ip)
	}
	if u, ip := l.tracked(); u != 0 || ip != 0 {
		t.Fatalf("panic left state behind (should count as aborted): %d users, %d ips", u, ip)
	}
	if !succeed(l, "alice", "10.0.0.1") {
		t.Fatal("alice must not be throttled after an aborted attempt")
	}
}

// Concurrent logins against the limiter, for the race detector.
func TestLoginConcurrent(t *testing.T) {
	var cfg Config
	l, _ := newTestLimiter(LoginLimitConfig{UserLimit: 3, IPLimit: 1000, Window: time.Minute, MaxEntries: 8})
	l.now = time.Now
	setLoginLimiter(&cfg, l)
	cfg.bindFn = func(username, password string) (*xldap.DNSearchResult, []string, error) {
		if password == "ok" {
			return &xldap.DNSearchResult{}, nil, nil
		}
		return nil, nil, ErrInvalidCredentials
	}
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 50 {
				pass := "bad"
				if j%3 == 0 {
					pass = "ok"
				}
				_, _, _ = cfg.Login(context.Background(), string(rune('a'+(i+j)%12)), pass, "10.0.0.1")
			}
		}()
	}
	wg.Wait()
	if u, ip := l.pending(); u != 0 || ip != 0 {
		t.Fatalf("reservations left after all logins finished: %d users, %d ips", u, ip)
	}
	if u, _ := l.tracked(); u > 8 {
		t.Fatalf("user table exceeds its bound: %d", u)
	}
}

// The no-match outcome of the user search is recognized positively.
func TestIsUserNotFound(t *testing.T) {
	d := newFakeDirectory(t, 0)
	cfg := d.config(t)
	conn, err := cfg.LDAP.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := cfg.LDAP.LookupBind(conn); err != nil {
		t.Fatal(err)
	}
	_, err = cfg.LDAP.LookupUsername(conn, "nosuchuser")
	if err == nil || !isUserNotFound(err) {
		t.Fatalf("expected the no-match error to be recognized, got %v", err)
	}
	d.failSearch("broken", ldap.LDAPResultInsufficientAccessRights)
	_, err = cfg.LDAP.LookupUsername(conn, "broken")
	if err == nil || isUserNotFound(err) {
		t.Fatalf("expected a directory error not to be taken as no match, got %v", err)
	}
}

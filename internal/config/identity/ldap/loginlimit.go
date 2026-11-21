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
	"strings"
	"sync"
	"time"
)

// Defaults for throttling failed LDAP logins. They are deliberately
// conservative: a legitimate user rarely mistypes a password ten times in
// fifteen minutes, while an online guessing attack is reduced to a few dozen
// guesses per hour per account. Clients behind one NAT or proxy share an IP
// address, so the per-IP limit is looser than the per-account one.
const (
	DefaultLoginFailureUserLimit = 10
	DefaultLoginFailureIPLimit   = 50
	DefaultLoginFailureWindow    = 15 * time.Minute

	// DefaultLoginFailureMaxEntries bounds the number of distinct keys
	// tracked per table (usernames and IP addresses), so that spraying
	// random usernames or source addresses cannot exhaust memory.
	DefaultLoginFailureMaxEntries = 10000
)

// LoginLimitConfig configures a LoginFailureLimiter. A zero limit disables
// that dimension of throttling.
type LoginLimitConfig struct {
	UserLimit  int
	IPLimit    int
	Window     time.Duration
	MaxEntries int
}

type loginFailure struct {
	failures int       // failed attempts in the current window
	pending  int       // attempts reserved but not yet finished
	start    time.Time // start of the current window (first failure)
}

type loginFailureTable struct {
	limit   int
	entries map[string]*loginFailure
}

// LoginFailureLimiter counts failed login attempts per username and per
// source IP address within a fixed window that starts at the first failure.
// Once either count reaches its limit, further attempts for that key are
// refused until the window ends.
//
// Callers Reserve an attempt before checking credentials and Finish it
// afterwards. Attempts in flight count against the limit, so that sending
// many requests concurrently cannot exceed the failure budget; a successful
// or aborted attempt releases its reservation and is never counted. Counters
// are kept in memory on each node and are reset when the LDAP configuration
// is reloaded.
//
// All methods are safe for concurrent use and on a nil receiver, which
// behaves as a disabled limiter.
type LoginFailureLimiter struct {
	mu         sync.Mutex
	window     time.Duration
	maxEntries int
	users      loginFailureTable
	ips        loginFailureTable
	now        func() time.Time
}

// NewLoginFailureLimiter returns a limiter for cfg, or nil when both limits
// are disabled.
func NewLoginFailureLimiter(cfg LoginLimitConfig) *LoginFailureLimiter {
	if cfg.UserLimit <= 0 && cfg.IPLimit <= 0 {
		return nil
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultLoginFailureWindow
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = DefaultLoginFailureMaxEntries
	}
	return &LoginFailureLimiter{
		window:     cfg.Window,
		maxEntries: cfg.MaxEntries,
		users:      loginFailureTable{limit: cfg.UserLimit, entries: make(map[string]*loginFailure)},
		ips:        loginFailureTable{limit: cfg.IPLimit, entries: make(map[string]*loginFailure)},
		now:        time.Now,
	}
}

// normalizeLoginUser folds the username the same way for known and unknown
// accounts, so that trivially different spellings share one budget and the
// throttling decision never depends on whether the account exists.
func normalizeLoginUser(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// Reserve reports whether a login attempt for username from sourceIP may
// proceed. When it returns true the caller must call Finish exactly once
// with the same arguments after the attempt completes.
func (l *LoginFailureLimiter) Reserve(username, sourceIP string) bool {
	if l == nil {
		return true
	}
	user := normalizeLoginUser(username)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if l.users.blocked(user, now, l.window) || l.ips.blocked(sourceIP, now, l.window) {
		return false
	}
	l.users.reserve(user, now, l.window, l.maxEntries)
	l.ips.reserve(sourceIP, now, l.window, l.maxEntries)
	return true
}

// Finish completes an attempt reserved with Reserve. Only failed attempts
// are counted; otherwise the reservation is simply released.
func (l *LoginFailureLimiter) Finish(username, sourceIP string, failed bool) {
	if l == nil {
		return
	}
	user := normalizeLoginUser(username)
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.users.finish(user, now, l.window, l.maxEntries, failed)
	l.ips.finish(sourceIP, now, l.window, l.maxEntries, failed)
}

// tracked returns the number of tracked usernames and IP addresses.
func (l *LoginFailureLimiter) tracked() (users, ips int) {
	if l == nil {
		return 0, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.users.entries), len(l.ips.entries)
}

func (t *loginFailureTable) enabled(key string) bool {
	return t.limit > 0 && key != ""
}

// expire starts a new window for e if the current one has ended, and drops
// the entry if nothing is left in it.
func (t *loginFailureTable) expire(key string, e *loginFailure, now time.Time, window time.Duration) bool {
	if e.failures > 0 && now.Sub(e.start) >= window {
		e.failures = 0
	}
	if e.failures == 0 && e.pending == 0 {
		delete(t.entries, key)
		return true
	}
	return false
}

func (t *loginFailureTable) blocked(key string, now time.Time, window time.Duration) bool {
	if !t.enabled(key) {
		return false
	}
	e, ok := t.entries[key]
	if !ok || t.expire(key, e, now, window) {
		return false
	}
	return e.failures+e.pending >= t.limit
}

func (t *loginFailureTable) lookupOrAdd(key string, now time.Time, window time.Duration, maxEntries int) *loginFailure {
	if e, ok := t.entries[key]; ok {
		return e
	}
	if len(t.entries) >= maxEntries {
		t.evict(now, window, maxEntries)
	}
	e := &loginFailure{start: now}
	t.entries[key] = e
	return e
}

func (t *loginFailureTable) reserve(key string, now time.Time, window time.Duration, maxEntries int) {
	if !t.enabled(key) {
		return
	}
	t.lookupOrAdd(key, now, window, maxEntries).pending++
}

func (t *loginFailureTable) finish(key string, now time.Time, window time.Duration, maxEntries int, failed bool) {
	if !t.enabled(key) {
		return
	}
	e, ok := t.entries[key]
	if ok && e.pending > 0 {
		e.pending--
	}
	if failed {
		if !ok {
			// The reservation was evicted; still count the failure.
			e = t.lookupOrAdd(key, now, window, maxEntries)
		}
		if e.failures == 0 || now.Sub(e.start) >= window {
			e.failures, e.start = 0, now
		}
		e.failures++
		return
	}
	if ok {
		t.expire(key, e, now, window)
	}
}

// evict makes room for one more entry: it drops every expired entry and, if
// the table is still full, the entries whose windows started first. Keys are
// attacker-controlled, so the table must stay bounded even if that means
// forgetting the oldest counters; the per-IP table limits how quickly a
// single client can churn the per-user table.
func (t *loginFailureTable) evict(now time.Time, window time.Duration, maxEntries int) {
	for k, e := range t.entries {
		t.expire(k, e, now, window)
	}
	for len(t.entries) >= maxEntries {
		var oldestKey string
		var oldest time.Time
		for k, e := range t.entries {
			if oldestKey == "" || e.start.Before(oldest) {
				oldestKey, oldest = k, e.start
			}
		}
		delete(t.entries, oldestKey)
	}
}

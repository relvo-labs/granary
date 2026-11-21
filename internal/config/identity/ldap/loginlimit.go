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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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

	// DefaultLoginFailureMinResponseTime is the minimum time a rejected
	// login takes, measured from the start of the attempt. It hides the
	// directory's timing difference between unknown accounts (rejected
	// before any password hash is computed) and wrong passwords.
	DefaultLoginFailureMinResponseTime = time.Second

	// MaxLoginFailureMinResponseTime caps the configurable minimum
	// response time, so that a typo cannot stall every failed login.
	MaxLoginFailureMinResponseTime = 30 * time.Second
)

// Upper bounds for the credentials of a login attempt. Longer values are
// rejected as invalid credentials before the limiter or the directory sees
// them; no real LDAP username or password comes close to these sizes.
const (
	MaxLoginUsernameLength = 512  // bytes
	MaxLoginPasswordLength = 1024 // bytes
)

// ValidLoginCredentialLengths reports whether username and password are
// within MaxLoginUsernameLength and MaxLoginPasswordLength.
func ValidLoginCredentialLengths(username, password string) bool {
	return len(username) <= MaxLoginUsernameLength && len(password) <= MaxLoginPasswordLength
}

// LoginLimitConfig configures a LoginFailureLimiter. A zero limit disables
// that dimension of throttling.
type LoginLimitConfig struct {
	UserLimit  int
	IPLimit    int
	Window     time.Duration
	MaxEntries int

	// MinResponseTime is the minimum duration of a rejected login; 0
	// disables it. It is applied by Config.Login, not by the limiter.
	MinResponseTime time.Duration
}

// loginKey is a keyed digest of a normalized username or source address.
// Only digests are stored, so that the memory held by the limiter does not
// depend on the length of attacker-supplied values.
type loginKey [sha256.Size]byte

type loginFailure struct {
	failures int       // failed attempts in the current window
	pending  int       // attempts reserved but not yet finished
	start    time.Time // start of the current window (see finish)
}

type loginFailureTable struct {
	limit   int
	entries map[loginKey]*loginFailure

	// While the table is full, pruneAt is the earliest time at which a
	// scan could free a slot; until then new keys are refused without
	// scanning. The zero value means a scan may succeed now.
	pruneAt time.Time
}

// LoginFailureLimiter counts failed login attempts per username and per
// source IP address within a fixed window. The window starts when the
// earliest failed attempt in it was reserved, not when the directory
// rejected it, so that the moment a key is admitted again does not reveal
// how long the directory took. Once either count reaches its limit, further
// attempts for that key are refused until the window ends.
//
// Callers Reserve an attempt before checking credentials and complete the
// returned LoginAttempt afterwards. Attempts in flight count against the
// limit, so that sending many requests concurrently cannot exceed the
// failure budget; a successful or aborted attempt releases its reservation
// and is never counted. Counters are kept in memory on each node and are
// reset when the LDAP configuration is reloaded.
//
// Each table holds at most MaxEntries keys. Entries with live failures or
// reservations are never dropped to make room; when a table is full of them,
// attempts for keys it does not already track are refused (fail closed)
// until entries expire.
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

	// hashKey is a random per-limiter key for the table digests, so that
	// collisions cannot be precomputed.
	hashKey [32]byte
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
	l := &LoginFailureLimiter{
		window:     cfg.Window,
		maxEntries: cfg.MaxEntries,
		users:      loginFailureTable{limit: cfg.UserLimit, entries: make(map[loginKey]*loginFailure)},
		ips:        loginFailureTable{limit: cfg.IPLimit, entries: make(map[loginKey]*loginFailure)},
		now:        time.Now,
	}
	// crypto/rand.Read never returns an error on supported platforms.
	_, _ = rand.Read(l.hashKey[:])
	return l
}

// normalizeLoginUser folds the username the same way for known and unknown
// accounts, so that trivially different spellings share one budget and the
// throttling decision never depends on whether the account exists.
func normalizeLoginUser(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func (l *LoginFailureLimiter) digest(s string) loginKey {
	var k loginKey
	h := hmac.New(sha256.New, l.hashKey[:])
	h.Write([]byte(s))
	h.Sum(k[:0])
	return k
}

// LoginAttempt is a reservation returned by LoginFailureLimiter.Reserve. It
// must be completed with Finish or Abort; only the first completion has an
// effect, so it is safe to defer Abort and call Finish on the normal path.
// A nil *LoginAttempt is valid and does nothing.
type LoginAttempt struct {
	l      *LoginFailureLimiter
	user   *loginFailure // nil when per-user throttling does not apply
	ip     *loginFailure // nil when per-IP throttling does not apply
	userK  loginKey
	ipK    loginKey
	start  time.Time // when the attempt was reserved
	closed bool      // guarded by l.mu
}

// Reserve reports whether a login attempt for username from sourceIP may
// proceed. When it does, the returned attempt must be completed exactly
// once; the reservation is bound to the entries it was taken on.
func (l *LoginFailureLimiter) Reserve(username, sourceIP string) (*LoginAttempt, bool) {
	if l == nil {
		return nil, true
	}
	user := normalizeLoginUser(username)
	useUser := l.users.enabled(user)
	useIP := l.ips.enabled(sourceIP)
	a := &LoginAttempt{l: l}
	if useUser {
		a.userK = l.digest(user)
	}
	if useIP {
		a.ipK = l.digest(sourceIP)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()

	var ue, ie *loginFailure
	if useUser {
		ue = l.users.lookup(a.userK, now, l.window)
		if ue != nil && ue.failures+ue.pending >= l.users.limit {
			return nil, false
		}
	}
	if useIP {
		ie = l.ips.lookup(a.ipK, now, l.window)
		if ie != nil && ie.failures+ie.pending >= l.ips.limit {
			return nil, false
		}
	}
	// Check capacity of both tables before creating anything, so that a
	// refused attempt leaves no state behind.
	if useUser && ue == nil && !l.users.hasRoom(now, l.window, l.maxEntries) {
		return nil, false
	}
	if useIP && ie == nil && !l.ips.hasRoom(now, l.window, l.maxEntries) {
		return nil, false
	}
	if useUser {
		if ue == nil {
			ue = &loginFailure{start: now}
			l.users.entries[a.userK] = ue
		}
		ue.pending++
		a.user = ue
	}
	if useIP {
		if ie == nil {
			ie = &loginFailure{start: now}
			l.ips.entries[a.ipK] = ie
		}
		ie.pending++
		a.ip = ie
	}
	a.start = now
	return a, true
}

// Finish completes the attempt. A failed attempt is counted against its
// username and source address as of the time it was reserved; otherwise the
// reservation is only released. Calls after the first completion are
// ignored.
func (a *LoginAttempt) Finish(failed bool) {
	if a == nil || a.l == nil {
		return
	}
	l := a.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if a.closed {
		return
	}
	a.closed = true
	now := l.now()
	if a.user != nil {
		l.users.finish(a.userK, a.user, a.start, now, l.window, failed)
	}
	if a.ip != nil {
		l.ips.finish(a.ipK, a.ip, a.start, now, l.window, failed)
	}
}

// Abort releases the reservation without counting a failure, unless the
// attempt was already completed. Use it in a defer so that a panic or an
// early return cannot leak the reservation.
func (a *LoginAttempt) Abort() {
	a.Finish(false)
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

// pending returns the number of attempts in flight per table.
func (l *LoginFailureLimiter) pending() (users, ips int) {
	if l == nil {
		return 0, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.users.entries {
		users += e.pending
	}
	for _, e := range l.ips.entries {
		ips += e.pending
	}
	return users, ips
}

func (t *loginFailureTable) enabled(key string) bool {
	return t.limit > 0 && key != ""
}

// expire starts a new window for e if the current one has ended, and drops
// the entry if nothing is left in it.
func (t *loginFailureTable) expire(key loginKey, e *loginFailure, now time.Time, window time.Duration) bool {
	if e.failures > 0 && now.Sub(e.start) >= window {
		e.failures = 0
	}
	if e.failures == 0 && e.pending == 0 {
		if t.entries[key] == e {
			delete(t.entries, key)
		}
		return true
	}
	return false
}

// lookup returns the live entry for key, or nil if there is none.
func (t *loginFailureTable) lookup(key loginKey, now time.Time, window time.Duration) *loginFailure {
	e, ok := t.entries[key]
	if !ok || t.expire(key, e, now, window) {
		return nil
	}
	return e
}

// hasRoom reports whether a new key can be added. When the table is full it
// drops entries whose window has ended and that have no attempt in flight;
// live counters and reservations are always kept.
func (t *loginFailureTable) hasRoom(now time.Time, window time.Duration, maxEntries int) bool {
	if len(t.entries) < maxEntries {
		return true
	}
	if now.Before(t.pruneAt) {
		return false
	}
	var next time.Time
	for k, e := range t.entries {
		if t.expire(k, e, now, window) {
			continue
		}
		if e.pending == 0 {
			if at := e.start.Add(window); next.IsZero() || at.Before(next) {
				next = at
			}
		}
	}
	if len(t.entries) < maxEntries {
		t.pruneAt = time.Time{}
		return true
	}
	// Entries with attempts in flight are freed when those attempts
	// finish, which resets pruneAt where needed (see finish).
	t.pruneAt = next
	return false
}

// finish completes an attempt on e that was reserved at reserved. A failure
// is placed in time by its reservation, which does not depend on the
// directory: the window starts at the earliest reservation among its
// failures. The result therefore does not depend on how long each attempt
// took or on the order in which concurrent attempts complete, as long as
// each completes within one window of being reserved.
func (t *loginFailureTable) finish(key loginKey, e *loginFailure, reserved, now time.Time, window time.Duration, failed bool) {
	if e.pending > 0 {
		e.pending--
	}
	if failed {
		switch {
		case e.failures == 0 || reserved.Sub(e.start) >= window:
			// First failure of a new window.
			e.failures, e.start = 1, reserved
		case e.start.Sub(reserved) >= window:
			// Reserved in a window that has already been replaced;
			// that window's failures no longer count.
		default:
			if reserved.Before(e.start) {
				e.start = reserved
			}
			e.failures++
		}
	}
	if t.expire(key, e, now, window) {
		return
	}
	if e.pending == 0 && !t.pruneAt.IsZero() {
		if at := e.start.Add(window); at.Before(t.pruneAt) {
			t.pruneAt = at
		}
	}
}

// loginResponseFloor delays rejected logins until a minimum time has passed
// since the attempt started.
//
// The wait deliberately does not end when the client goes away: an HTTP/1
// client can half-close its connection after sending the request, which
// cancels the request context while the client can still read the response.
// Ending the wait then would let the client observe the rejection (or the
// connection closing) at the directory's own pace. The wait is bounded by
// min, which configuration limits to MaxLoginFailureMinResponseTime.
type loginResponseFloor struct {
	min   time.Duration
	now   func() time.Time
	sleep func(d time.Duration)
}

func newLoginResponseFloor(minDuration time.Duration) *loginResponseFloor {
	if minDuration <= 0 {
		return nil
	}
	return &loginResponseFloor{min: minDuration, now: time.Now, sleep: time.Sleep}
}

func (f *loginResponseFloor) start() time.Time {
	if f == nil {
		return time.Time{}
	}
	return f.now()
}

// wait blocks until the minimum response time has elapsed since start. It
// never blocks for longer than the minimum response time itself, even if
// the clock moved backwards.
func (f *loginResponseFloor) wait(start time.Time) {
	if f == nil {
		return
	}
	d := f.min - f.now().Sub(start)
	if d > f.min {
		d = f.min
	}
	if d > 0 {
		f.sleep(d)
	}
}

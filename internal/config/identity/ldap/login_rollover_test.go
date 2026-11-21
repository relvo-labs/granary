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
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	xldap "github.com/minio/pkg/v3/ldap"
)

// loginSim runs concurrent logins against a fake clock as a discrete-event
// simulation. Exactly one goroutine runs at a time: the scheduler hands
// control to a login over a channel and waits until it parks on the clock or
// returns, so the outcome depends only on the scheduled times.
type loginSim struct {
	clk     *fakeClock
	seq     int
	wakeups []simWakeup
	yield   chan struct{}
}

type simWakeup struct {
	at  time.Time
	seq int
	ch  chan struct{}
}

// sleepUntil parks the calling login until the clock reaches at.
func (s *loginSim) sleepUntil(at time.Time) {
	ch := make(chan struct{})
	s.seq++
	s.wakeups = append(s.wakeups, simWakeup{at: at, seq: s.seq, ch: ch})
	s.yield <- struct{}{}
	<-ch
}

type simRequest struct {
	name string
	at   time.Duration // offset from the simulation start
}

// run starts each request at its offset and returns one line per request:
// its outcome and how long it took on the fake clock.
func (s *loginSim) run(t *testing.T, cfg *Config, user, ip func(name string) string, reqs []simRequest) []string {
	t.Helper()
	t0 := s.clk.now()
	results := make([]string, len(reqs))
	next := 0
	for next < len(reqs) || len(s.wakeups) > 0 {
		sort.SliceStable(s.wakeups, func(i, j int) bool {
			if !s.wakeups[i].at.Equal(s.wakeups[j].at) {
				return s.wakeups[i].at.Before(s.wakeups[j].at)
			}
			return s.wakeups[i].seq < s.wakeups[j].seq
		})
		// Wakeups due no later than the next request start run first.
		if len(s.wakeups) > 0 && (next == len(reqs) || !s.wakeups[0].at.After(t0.Add(reqs[next].at))) {
			w := s.wakeups[0]
			s.wakeups = s.wakeups[1:]
			if w.at.After(s.clk.now()) {
				s.clk.t = w.at
			}
			close(w.ch)
			<-s.yield
			continue
		}
		i := next
		next++
		s.clk.t = t0.Add(reqs[i].at)
		go func() {
			r := reqs[i]
			start := s.clk.now()
			err := testLogin(context.Background(), cfg, user(r.name), "guess", ip(r.name))
			var outcome string
			switch {
			case errors.Is(err, ErrLoginThrottled):
				outcome = "throttled"
			case errors.Is(err, ErrInvalidCredentials):
				outcome = "invalid"
			default:
				outcome = fmt.Sprintf("unexpected %v", err)
			}
			results[i] = fmt.Sprintf("%s@%v: %s after %v", r.name, r.at, outcome, s.clk.now().Sub(start))
			s.yield <- struct{}{}
		}()
		<-s.yield
	}
	return results
}

// rolloverOutcome replays the window-rollover probe of the review against a
// directory that rejects every attempt after directoryTime with err.
func rolloverOutcome(t *testing.T, perIP bool, directoryTime time.Duration, rejection error) []string {
	t.Helper()
	const (
		window      = time.Minute
		minResponse = time.Second
		limit       = 2
	)
	sim := &loginSim{clk: &fakeClock{t: time.Unix(1_700_000_000, 0)}, yield: make(chan struct{})}
	lc := LoginLimitConfig{UserLimit: limit, IPLimit: 1000, Window: window}
	user := func(string) string { return "probe" }
	ip := func(string) string { return "10.0.0.1" }
	if perIP {
		// Distinct usernames from one address: only the per-IP limit binds.
		lc = LoginLimitConfig{UserLimit: 1000, IPLimit: limit, Window: window}
		user = func(name string) string { return "probe-" + name }
		ip = func(string) string { return "10.0.0.9" }
	}
	var cfg Config
	l, _ := newTestLimiter(lc)
	setLoginFakeClock(&cfg, l, sim.clk, minResponse, func(d time.Duration) {
		sim.sleepUntil(sim.clk.now().Add(d))
	})
	cfg.bindFn = func(username, password string) (*xldap.DNSearchResult, []string, error) {
		sim.sleepUntil(sim.clk.now().Add(directoryTime))
		return nil, nil, rejection
	}
	ms := time.Millisecond
	reqs := []simRequest{
		{"old", 0},              // opens the window that is about to end
		{"A", 59900 * ms},       // in flight while the window ends
		{"B", 60050 * ms},       // first request after the window ended
		{"C", 60300 * ms},       // concurrent probes while A and B are in flight
		{"D", 60300 * ms},       //
		{"E", 60950 * ms},       // after A's minimum response time
		{"F", 61100 * ms},       // after B's minimum response time
		{"G", 119950 * ms},      // after the new window ended
		{"H", 119950*ms + 1*ms}, //
	}
	out := sim.run(t, &cfg, user, ip, reqs)
	if u, ipn := l.pending(); u != 0 || ipn != 0 {
		t.Fatalf("reservations left: %d users, %d ips", u, ipn)
	}
	return out
}

// An attempt that is still in flight when a failure window ends must not be
// placed in the old or the new window depending on how fast the directory
// rejected it: with a per-key limit of 2, a fast rejection of an unknown
// account would otherwise let a later probe through while a slower wrong
// password check gets HTTP 429, revealing that the account exists although
// both directory times are below the minimum response time.
func TestLoginWindowRolloverIndependentOfDirectoryTime(t *testing.T) {
	directories := []struct {
		name string
		time time.Duration
		err  error
	}{
		{"unknown account 10ms", 10 * time.Millisecond, fmt.Errorf("%w: unable to find user DN", ErrInvalidCredentials)},
		{"wrong password 200ms", 200 * time.Millisecond, fmt.Errorf("%w: LDAP auth failed", ErrInvalidCredentials)},
		{"unusable account 10ms", 10 * time.Millisecond, fmt.Errorf("%w: %w", ErrInvalidCredentials, ErrUnusableAccount)},
		{"wrong password 990ms", 990 * time.Millisecond, fmt.Errorf("%w: LDAP auth failed", ErrInvalidCredentials)},
	}
	for _, perIP := range []bool{false, true} {
		dim := "per-username"
		if perIP {
			dim = "per-IP"
		}
		t.Run(dim, func(t *testing.T) {
			ref := rolloverOutcome(t, perIP, directories[0].time, directories[0].err)
			t.Logf("%s:\n  %s", directories[0].name, strings.Join(ref, "\n  "))
			for _, d := range directories[1:] {
				got := rolloverOutcome(t, perIP, d.time, d.err)
				if strings.Join(got, "\n") != strings.Join(ref, "\n") {
					t.Errorf("outcome depends on directory time:\n%s:\n  %s\n%s:\n  %s",
						directories[0].name, strings.Join(ref, "\n  "), d.name, strings.Join(got, "\n  "))
				}
			}
		})
	}
}

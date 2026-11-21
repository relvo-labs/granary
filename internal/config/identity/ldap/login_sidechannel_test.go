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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	xldap "github.com/minio/pkg/v3/ldap"
)

// Regression tests for timing and state side channels of rejected logins.
// They use the helpers in loginlimit_adapter_test.go only.

// A canceled request context must not end the minimum response time early:
// the caller writes the rejection as soon as Login returns.
func TestLoginMinResponseTimeIgnoresCancellation(t *testing.T) {
	const minResponse = 300 * time.Millisecond
	d := newFakeDirectory(t, 0)
	cfg := d.config(t)
	setLoginMinResponseTime(cfg, minResponse)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	err := testLogin(ctx, cfg, "nosuchuser", "guess", "10.0.0.1")
	took := time.Since(start)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
	if took < minResponse {
		t.Fatalf("rejection with a canceled context returned after %v, before the minimum response time %v", took, minResponse)
	}
}

// An HTTP/1 client that sends a complete request and then half-closes the
// connection makes the Go server cancel the request context. The rejection
// (and closing the connection) must still not be observable before the
// minimum response time.
func TestLoginMinResponseTimeSurvivesHalfClose(t *testing.T) {
	const minResponse = 400 * time.Millisecond
	d := newFakeDirectory(t, 0)
	cfg := d.config(t)
	setLoginMinResponseTime(cfg, minResponse)

	canceled := make(chan bool, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		// Same shape as the STS handler: the request context goes to
		// Login, and the rejection is written when Login returns.
		err := testLogin(r.Context(), cfg, r.Form.Get("u"), r.Form.Get("p"), "10.0.0.1")
		canceled <- r.Context().Err() != nil
		if errors.Is(err, ErrInvalidCredentials) {
			http.Error(w, "invalid username or password", http.StatusBadRequest)
			return
		}
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("expected a TCP connection, got %T", conn)
	}
	body := url.Values{"u": {"nosuchuser"}, "p": {"guess"}}.Encode()
	req := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s",
		srv.Listener.Addr(), len(body), body)
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	start := time.Now()
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	if err := tcp.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// The first observable event is either response bytes or the
	// connection being closed (n == 0 with an error).
	var first [1]byte
	n, rerr := conn.Read(first[:])
	took := time.Since(start)
	rest, _ := io.ReadAll(conn)
	resp := string(first[:n]) + string(rest)

	if took < minResponse {
		t.Fatalf("half-closed request observed a result after %v (read %d bytes, err %v), before the minimum response time %v", took, n, rerr, minResponse)
	}
	if !strings.HasPrefix(resp, "HTTP/1.1 400 ") {
		t.Fatalf("expected the uniform 400 rejection, got %q (read err %v)", resp, rerr)
	}
	select {
	case c := <-canceled:
		if !c {
			t.Log("note: the server did not cancel the request context on half-close")
		}
	default:
	}
}

// failureExpiry returns the earliest fake-clock offset from the start of a
// rejected login at which the candidate username and source address are
// admitted again, probing in steps of step.
func failureExpiry(t *testing.T, directoryTime time.Duration) (userFree, ipFree time.Duration) {
	t.Helper()
	const window = time.Minute
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	t0 := clk.now()
	var cfg Config
	l, _ := newTestLimiter(LoginLimitConfig{UserLimit: 1, IPLimit: 1, Window: window})
	setLoginFakeClock(&cfg, l, clk, 30*time.Second, func(d time.Duration) { clk.advance(d) })
	cfg.bindFn = func(username, password string) (*xldap.DNSearchResult, []string, error) {
		clk.advance(directoryTime)
		return nil, nil, ErrInvalidCredentials
	}
	if err := testLogin(context.Background(), &cfg, "candidate", "guess", "10.0.0.9"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials, got %v", err)
	}
	probe := func(user, ip string) time.Duration {
		for off := window - 2*time.Second; off <= window+40*time.Second; off += 250 * time.Millisecond {
			clk.t = t0.Add(off)
			if finish, ok := testReserve(l, user, ip); ok {
				finish(false)
				return off
			}
		}
		t.Fatalf("%s/%s never admitted again", user, ip)
		return 0
	}
	userFree = probe("candidate", "10.0.0.1")
	ipFree = probe("other-user", "10.0.0.9")
	return userFree, ipFree
}

// The failure window must not depend on how long the directory took to
// reject the attempt; otherwise the moment a throttled key is admitted
// again reveals the hidden directory time.
func TestLoginFailureExpiryIndependentOfDirectoryTime(t *testing.T) {
	fastUser, fastIP := failureExpiry(t, 10*time.Millisecond)
	slowUser, slowIP := failureExpiry(t, 5*time.Second)
	if fastUser != slowUser || fastIP != slowIP {
		t.Fatalf("failure expiry depends on directory time: fast rejection frees user/ip at %v/%v, slow rejection at %v/%v",
			fastUser, fastIP, slowUser, slowIP)
	}
	if fastUser != time.Minute || fastIP != time.Minute {
		t.Fatalf("expected the window to end one window after the attempt started, got user %v ip %v", fastUser, fastIP)
	}
}

// Concurrent failures for one key must give the same window whatever order
// the directory completes them in.
func TestLoginFailureLimiterWindowIndependentOfCompletionOrder(t *testing.T) {
	const window = time.Minute
	expiry := func(firstDoneFirst bool) time.Duration {
		l, clk := newTestLimiter(LoginLimitConfig{UserLimit: 100, IPLimit: 2, Window: window})
		t0 := clk.now()
		a, ok := testReserve(l, "a", "10.0.0.9")
		if !ok {
			t.Fatal("first attempt refused")
		}
		clk.advance(2 * time.Second)
		b, ok := testReserve(l, "b", "10.0.0.9")
		if !ok {
			t.Fatal("second attempt refused")
		}
		clk.advance(3 * time.Second)
		if firstDoneFirst {
			a(true)
			b(true)
		} else {
			b(true)
			a(true)
		}
		for off := window - 2*time.Second; off <= window+10*time.Second; off += 250 * time.Millisecond {
			clk.t = t0.Add(off)
			if finish, ok := testReserve(l, "c", "10.0.0.9"); ok {
				finish(false)
				return off
			}
		}
		t.Fatal("address never admitted again")
		return 0
	}
	inOrder, reversed := expiry(true), expiry(false)
	if inOrder != reversed {
		t.Fatalf("window depends on completion order: %v in order, %v reversed", inOrder, reversed)
	}
	if inOrder != window {
		t.Fatalf("expected the window to end one window after the first attempt started, got %v", inOrder)
	}
}

// A username whose search yields no usable single entry (several matching
// entries, or a malformed entry DN) depends on the account, so it must look
// exactly like a wrong password: same error class, the same minimum response
// time, the same limiter state while waiting, and the same failure count, so that it is throttled after the same number of attempts. If it
// were not counted, a client could tell such a name apart by never getting
// HTTP 429 for it.
func TestLoginUnusableLookupIsUniformRejection(t *testing.T) {
	const (
		minResponse = time.Second
		userLimit   = 2
	)
	d := newFakeDirectory(t, 0)
	d.addUser("alice", fakeUser{password: "alice-pass"})
	d.returnEntries("twin", d.userDN("twin"), "uid=twin,ou=other,"+d.baseDN)
	d.returnEntries("mangled", "uid=mangled,,=bad")
	cfg := d.config(t)
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	l, _ := newTestLimiter(LoginLimitConfig{UserLimit: userLimit, IPLimit: 100, Window: time.Minute})
	var waits []time.Duration
	var pendingDuringWait [][2]int
	setLoginFakeClock(cfg, l, clk, minResponse, func(dur time.Duration) {
		waits = append(waits, dur)
		u, ip := l.pending()
		pendingDuringWait = append(pendingDuringWait, [2]int{u, ip})
	})
	// alice with a wrong password is the reference behavior. Each name
	// uses its own address so that only the per-username limit applies.
	var refPending [2]int
	for n, user := range []string{"alice", "twin", "mangled"} {
		ip := fmt.Sprintf("10.0.0.%d", n+1)
		for i := range userLimit {
			waits, pendingDuringWait = nil, nil
			err := testLogin(context.Background(), cfg, user, "guess", ip)
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("%s attempt %d: expected the uniform credential rejection, got %v", user, i+1, err)
			}
			if len(waits) != 1 || waits[0] != minResponse {
				t.Fatalf("%s attempt %d: expected one wait of %v, got %v", user, i+1, minResponse, waits)
			}
			if user == "alice" {
				refPending = pendingDuringWait[0]
			} else if pendingDuringWait[0] != refPending {
				t.Fatalf("%s attempt %d: limiter state during the wait %v differs from a wrong password's %v", user, i+1, pendingDuringWait[0], refPending)
			}
		}
		waits = nil
		if err := testLogin(context.Background(), cfg, user, "guess", ip); !errors.Is(err, ErrLoginThrottled) {
			t.Fatalf("%s: expected throttling after %d failed attempts, like a wrong password, got %v", user, userLimit, err)
		}
		if len(waits) != 0 {
			t.Fatalf("%s: throttled attempt waited %v", user, waits)
		}
	}
	if u, ip := l.pending(); u != 0 || ip != 0 {
		t.Fatalf("reservations left: %d users, %d ips", u, ip)
	}
}

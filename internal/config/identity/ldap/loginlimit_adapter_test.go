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
	"time"
)

// The helpers below are the only place where the regression tests in
// loginlimit_regress_test.go touch the limiter and login API, so that the
// same tests can be run against earlier revisions of that API.

// testReserve reserves an attempt and returns its completion function.
func testReserve(l *LoginFailureLimiter, user, ip string) (func(failed bool), bool) {
	a, ok := l.Reserve(user, ip)
	if !ok {
		return nil, false
	}
	return a.Finish, true
}

// retainedKeyBytes returns the number of bytes of table keys held by l.
func retainedKeyBytes(l *LoginFailureLimiter) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for k := range l.users.entries {
		n += len(k)
	}
	for k := range l.ips.entries {
		n += len(k)
	}
	return n
}

// testLogin runs one STS login attempt the way the STS handler does.
func testLogin(ctx context.Context, cfg *Config, user, pass, ip string) error {
	_, _, err := cfg.Login(ctx, user, pass, ip)
	return err
}

// setLoginMinResponseTime sets the minimum response time of rejected logins.
func setLoginMinResponseTime(cfg *Config, d time.Duration) {
	cfg.loginFloor = newLoginResponseFloor(d)
}

// setLoginLimiter sets the failed-login limiter of cfg.
func setLoginLimiter(cfg *Config, l *LoginFailureLimiter) {
	cfg.loginLimiter = l
}

// setLoginFakeClock makes cfg use l as its limiter and both of them use clk.
// Rejections wait for minDuration; each wait is passed to onWait instead of
// sleeping.
func setLoginFakeClock(cfg *Config, l *LoginFailureLimiter, clk *fakeClock, minDuration time.Duration, onWait func(time.Duration)) {
	l.now = clk.now
	cfg.loginLimiter = l
	cfg.loginFloor = &loginResponseFloor{
		min: minDuration,
		now: clk.now,
		sleep: func(d time.Duration) {
			onWait(d)
		},
	}
}

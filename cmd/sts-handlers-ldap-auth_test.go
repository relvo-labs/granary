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

package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
)

// ldapSTSResult is the externally observable outcome of an
// AssumeRoleWithLDAPIdentity call, without per-request identifiers.
type ldapSTSResult struct {
	Status  int
	Code    string
	Message string
}

func (s *TestSuiteIAM) postLDAPSTS(c *check, username, password string) ldapSTSResult {
	c.Helper()
	form := url.Values{}
	form.Set("Action", ldapIdentity)
	form.Set("Version", stsAPIVersion)
	form.Set(stsLDAPUsername, username)
	form.Set(stsLDAPPassword, password)

	req, err := http.NewRequest(http.MethodPost, s.endPoint+SlashSeparator, strings.NewReader(form.Encode()))
	if err != nil {
		c.Fatalf("unable to create STS request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.TestSuiteCommon.client.Do(req)
	if err != nil {
		c.Fatalf("STS request failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.Fatalf("unable to read STS response: %v", err)
	}
	res := ldapSTSResult{Status: resp.StatusCode}
	if resp.StatusCode == http.StatusOK {
		return res
	}
	var stsErr STSErrorResponse
	if err := xml.Unmarshal(body, &stsErr); err != nil {
		c.Fatalf("unable to parse STS error response %q: %v", string(body), err)
	}
	res.Code = stsErr.Error.Code
	res.Message = stsErr.Error.Message
	return res
}

const (
	testLDAPFailureUserLimit = 3
	// The window is long enough never to expire during the test; expiry is
	// covered with a controllable clock in internal/config/identity/ldap.
	testLDAPFailureWindow = time.Hour
	// Lower bounds on durations are deterministic; the test never asserts
	// that a request is fast.
	testLDAPMinResponseTime = 300 * time.Millisecond
)

// timedPostLDAPSTS is postLDAPSTS that also returns how long the call took.
func (s *TestSuiteIAM) timedPostLDAPSTS(c *check, username, password string) (ldapSTSResult, time.Duration) {
	c.Helper()
	start := time.Now()
	r := s.postLDAPSTS(c, username, password)
	return r, time.Since(start)
}

// halfClosedPostLDAPSTS sends an LDAP STS request over a raw connection,
// closes the writing side right after the request (which makes the server
// cancel the request context), and returns the response status and the time
// until the first observable result: response bytes or connection closure.
func (s *TestSuiteIAM) halfClosedPostLDAPSTS(c *check, username, password string) (int, time.Duration) {
	c.Helper()
	u, err := url.Parse(s.endPoint)
	if err != nil {
		c.Fatalf("invalid endpoint %q: %v", s.endPoint, err)
	}
	form := url.Values{}
	form.Set("Action", ldapIdentity)
	form.Set("Version", stsAPIVersion)
	form.Set(stsLDAPUsername, username)
	form.Set(stsLDAPPassword, password)
	body := form.Encode()
	req := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s",
		u.Host, len(body), body)

	var conn net.Conn
	var closeWrite func() error
	if s.secure {
		tc, err := tls.Dial("tcp", u.Host, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			c.Fatalf("unable to connect: %v", err)
		}
		conn, closeWrite = tc, tc.CloseWrite
	} else {
		nc, err := net.Dial("tcp", u.Host)
		if err != nil {
			c.Fatalf("unable to connect: %v", err)
		}
		conn, closeWrite = nc, nc.(*net.TCPConn).CloseWrite
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(testDefaultTimeout))
	start := time.Now()
	if _, err := io.WriteString(conn, req); err != nil {
		c.Fatalf("unable to send STS request: %v", err)
	}
	if err := closeWrite(); err != nil {
		c.Fatalf("unable to half-close the connection: %v", err)
	}
	br := bufio.NewReader(conn)
	if _, err := br.Peek(1); err != nil {
		return 0, time.Since(start)
	}
	took := time.Since(start)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		c.Fatalf("unable to read STS response: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode, took
}

// TestIAMWithLDAPAuthFailureServerSuite checks that LDAP STS logins do not
// reveal whether an account exists and that repeated failures are throttled
// (CVE-2026-33419 / GHSA-jv87-32hw-hh99). It needs a test LDAP server.
func TestIAMWithLDAPAuthFailureServerSuite(t *testing.T) {
	ldapServer := os.Getenv(EnvTestLDAPServer)
	if ldapServer == "" {
		t.Skipf("Skipping LDAP test as no LDAP server is provided via %s", EnvTestLDAPServer)
	}
	for i, testCase := range iamTestSuites {
		t.Run(
			fmt.Sprintf("Test: %d, ServerType: %s", i+1, testCase.ServerTypeDescription),
			func(t *testing.T) {
				c := &check{t, testCase.serverType}
				suite := testCase

				suite.SetUpSuite(c)
				suite.SetUpLDAP(c, ldapServer)
				suite.TestLDAPSTSAuthFailures(c)
				suite.TearDownSuite(c)
			},
		)
	}
}

func (s *TestSuiteIAM) TestLDAPSTSAuthFailures(c *check) {
	ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
	defer cancel()

	const (
		validUser   = "dillon"
		validPass   = "dillon"
		missingUser = "nosuchuser-gx71"
	)

	// A policy is needed for the valid user, so that a correct password
	// actually yields credentials.
	userReq := madmin.PolicyAssociationReq{
		Policies: []string{"readwrite"},
		User:     "uid=dillon,ou=people,ou=swengg,dc=min,dc=io",
	}
	if _, err := s.adm.AttachPolicyLDAP(ctx, userReq); err != nil {
		c.Fatalf("Unable to attach user policy: %v", err)
	}
	defer func() {
		if _, err := s.adm.DetachPolicyLDAP(ctx, userReq); err != nil {
			c.Fatalf("Unable to detach user policy: %v", err)
		}
	}()

	// 1. An unknown account and a wrong password are indistinguishable.
	missing := s.postLDAPSTS(c, missingUser, "wrong-password")
	wrongPass := s.postLDAPSTS(c, validUser, "wrong-password")
	if missing.Status == http.StatusOK || wrongPass.Status == http.StatusOK {
		c.Fatalf("expected failed logins, got %+v and %+v", missing, wrongPass)
	}
	if missing != wrongPass {
		c.Fatalf("unknown user and wrong password responses differ:\n unknown user:   %+v\n wrong password: %+v", missing, wrongPass)
	}
	for _, leak := range []string{validUser, missingUser, "DN", "uid="} {
		if strings.Contains(missing.Message, leak) {
			c.Fatalf("failure message %q leaks %q", missing.Message, leak)
		}
	}

	// Over-long credentials get the same response, without reaching the
	// directory or the limiter.
	if r := s.postLDAPSTS(c, strings.Repeat("x", 600), "wrong-password"); r != wrongPass {
		c.Fatalf("over-long username response differs:\n over-long:      %+v\n wrong password: %+v", r, wrongPass)
	}

	// Lower the throttling limits so that they can be exercised quickly. The
	// restart also starts with fresh counters.
	_, err := s.adm.SetConfigKV(ctx, fmt.Sprintf(
		"identity_ldap login_failure_user_limit=%d login_failure_ip_limit=1000 login_failure_window=%s login_failure_min_response_time=%s",
		testLDAPFailureUserLimit, testLDAPFailureWindow, testLDAPMinResponseTime))
	if err != nil {
		c.Fatalf("unable to configure LDAP login throttling: %v", err)
	}
	s.RestartIAMSuite(c)

	// The configuration change keeps the uniform failure response, and
	// every rejection takes at least the minimum response time.
	for _, user := range []string{validUser, missingUser} {
		r, took := s.timedPostLDAPSTS(c, user, "wrong-password")
		if r != wrongPass {
			c.Fatalf("unexpected response after reconfiguration: %+v", r)
		}
		if took < testLDAPMinResponseTime {
			c.Fatalf("rejection for %q took %v, less than the minimum response time %v", user, took, testLDAPMinResponseTime)
		}
	}

	// A client that half-closes its connection after the request makes the
	// server cancel the request context; the rejection must still not be
	// observable (as a response or as connection closure) before the
	// minimum response time. A separate unknown username keeps the
	// per-user counts below unchanged.
	if status, took := s.halfClosedPostLDAPSTS(c, "nosuchuser-halfclose", "wrong-password"); took < testLDAPMinResponseTime || status != wrongPass.Status {
		c.Fatalf("half-closed rejection: status %d after %v, want status %d no earlier than %v", status, took, wrongPass.Status, testLDAPMinResponseTime)
	}

	// 2. Successful logins are never counted as failures.
	for i := range testLDAPFailureUserLimit + 1 {
		if r := s.postLDAPSTS(c, validUser, validPass); r.Status != http.StatusOK {
			c.Fatalf("successful login %d unexpectedly failed: %+v", i+1, r)
		}
	}

	// 3. Reach the per-user failure limit for both accounts (one failure
	// each was already recorded since the restart).
	for range testLDAPFailureUserLimit - 1 {
		if r := s.postLDAPSTS(c, validUser, "wrong-password"); r != wrongPass {
			c.Fatalf("unexpected response before limit: %+v", r)
		}
		if r := s.postLDAPSTS(c, missingUser, "wrong-password"); r != wrongPass {
			c.Fatalf("unexpected response before limit: %+v", r)
		}
	}

	// 4. Once throttled, even the correct password is refused, and the
	// throttled response is identical for known and unknown accounts.
	throttledValid := s.postLDAPSTS(c, validUser, validPass)
	throttledMissing := s.postLDAPSTS(c, missingUser, "wrong-password")
	if throttledValid.Status != http.StatusTooManyRequests {
		c.Fatalf("expected throttled login, got %+v", throttledValid)
	}
	if throttledValid != throttledMissing {
		c.Fatalf("throttled responses differ:\n known user:   %+v\n unknown user: %+v", throttledValid, throttledMissing)
	}
}

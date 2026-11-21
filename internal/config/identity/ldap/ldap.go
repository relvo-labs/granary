// Copyright (c) 2015-2022 MinIO, Inc.
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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/minio/minio-go/v7/pkg/set"
	xldap "github.com/minio/pkg/v3/ldap"
	"github.com/relvo-labs/granary/internal/auth"
)

// LookupUserDN searches for the full DN and groups of a given short/login
// username.
func (l *Config) LookupUserDN(username string) (*xldap.DNSearchResult, []string, error) {
	conn, err := l.LDAP.Connect()
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	// Bind to the lookup user account
	if err = l.LDAP.LookupBind(conn); err != nil {
		return nil, nil, err
	}

	// Lookup user DN
	lookupRes, err := l.LDAP.LookupUsername(conn, username)
	if err != nil {
		errRet := fmt.Errorf("Unable to find user DN: %w", err)
		return nil, nil, errRet
	}

	groups, err := l.LDAP.SearchForUserGroups(conn, username, lookupRes.ActualDN)
	if err != nil {
		return nil, nil, err
	}

	return lookupRes, groups, nil
}

// GetValidatedDNForUsername checks if the given username exists in the LDAP directory.
// The given username could be just the short "login" username or the full DN.
//
// When the username/DN is found, the full DN returned by the **server** is
// returned, otherwise the returned string is empty. The value returned here is
// the value sent by the LDAP server and is used in minio as the server performs
// LDAP specific normalization (including Unicode normalization).
//
// If the user is not found, err = nil, otherwise, err != nil.
func (l *Config) GetValidatedDNForUsername(username string) (*xldap.DNSearchResult, error) {
	conn, err := l.LDAP.Connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Bind to the lookup user account
	if err = l.LDAP.LookupBind(conn); err != nil {
		return nil, err
	}

	// Check if the passed in username is a valid DN.
	if !l.ParsesAsDN(username) {
		// We consider it as a login username and attempt to check it exists in
		// the directory.
		bindDN, err := l.LDAP.LookupUsername(conn, username)
		if err != nil {
			if strings.Contains(err.Error(), "User DN not found for") {
				return nil, nil
			}
			return nil, fmt.Errorf("Unable to find user DN: %w", err)
		}
		return bindDN, nil
	}

	// Since the username parses as a valid DN, check that it exists and is
	// under a configured base DN in the LDAP directory.
	validDN, isUnderBaseDN, err := l.GetValidatedUserDN(conn, username)
	if err == nil && !isUnderBaseDN {
		// Not under any configured base DN, so treat as not found.
		return nil, nil
	}
	return validDN, err
}

// GetValidatedUserDN validates the given user DN. Will error out if conn is nil. The returned
// boolean is true iff the user DN is found under one of the LDAP user base DNs.
func (l *Config) GetValidatedUserDN(conn *ldap.Conn, userDN string) (*xldap.DNSearchResult, bool, error) {
	return l.GetValidatedDNUnderBaseDN(conn, userDN,
		l.LDAP.GetUserDNSearchBaseDistNames(), l.LDAP.GetUserDNAttributesList())
}

// GetValidatedGroupDN validates the given group DN. If conn is nil, creates a
// connection. The returned boolean is true iff the group DN is found under one
// of the configured LDAP base DNs.
func (l *Config) GetValidatedGroupDN(conn *ldap.Conn, groupDN string) (*xldap.DNSearchResult, bool, error) {
	if conn == nil {
		var err error
		conn, err = l.LDAP.Connect()
		if err != nil {
			return nil, false, err
		}
		defer conn.Close()

		// Bind to the lookup user account
		if err = l.LDAP.LookupBind(conn); err != nil {
			return nil, false, err
		}
	}

	return l.GetValidatedDNUnderBaseDN(conn, groupDN,
		l.LDAP.GetGroupSearchBaseDistNames(), nil)
}

// GetValidatedDNUnderBaseDN checks if the given DN exists in the LDAP
// directory.
//
// The `NormDN` value returned here in the search result may not be equal to the
// input DN, as LDAP equality is not a simple Golang string equality. However,
// we assume the value returned by the LDAP server is canonical. Additionally,
// the attribute type names in the DN are lower-cased.
//
// Return values:
//
// If the DN is found, the normalized (string) value and any requested
// attributes are returned and error is nil.
//
// If the DN is not found, a nil result and error are returned.
//
// The returned boolean is true iff the DN is found under one of the LDAP
// subtrees listed in `baseDNList`.
func (l *Config) GetValidatedDNUnderBaseDN(conn *ldap.Conn, dn string, baseDNList []xldap.BaseDNInfo, attrs []string) (*xldap.DNSearchResult, bool, error) {
	if len(baseDNList) == 0 {
		return nil, false, errors.New("no Base DNs given")
	}

	// Check that DN exists in the LDAP directory.
	searchRes, err := xldap.LookupDN(conn, dn, attrs)
	if err != nil {
		return nil, false, fmt.Errorf("Error looking up DN %s: %w", dn, err)
	}
	if searchRes == nil {
		return nil, false, nil
	}

	// This will not return an error as the argument is validated to be a DN.
	pdn, _ := ldap.ParseDN(searchRes.NormDN)

	// Check that the DN is under a configured base DN in the LDAP
	// directory.
	for _, baseDN := range baseDNList {
		if baseDN.Parsed.AncestorOf(pdn) {
			return searchRes, true, nil
		}
	}

	// Not under any configured base DN so return false.
	return searchRes, false, nil
}

// GetValidatedDNWithGroups - Gets validated DN from given DN or short username
// and returns the DN and the groups the user is a member of.
//
// If username is required in group search but a DN is passed, no groups are
// returned.
func (l *Config) GetValidatedDNWithGroups(username string) (*xldap.DNSearchResult, []string, error) {
	conn, err := l.LDAP.Connect()
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	// Bind to the lookup user account
	if err = l.LDAP.LookupBind(conn); err != nil {
		return nil, nil, err
	}

	var lookupRes *xldap.DNSearchResult
	shortUsername := ""
	// Check if the passed in username is a valid DN.
	if !l.ParsesAsDN(username) {
		// We consider it as a login username and attempt to check it exists in
		// the directory.
		lookupRes, err = l.LDAP.LookupUsername(conn, username)
		if err != nil {
			if strings.Contains(err.Error(), "User DN not found for") {
				return nil, nil, nil
			}
			return nil, nil, fmt.Errorf("Unable to find user DN: %w", err)
		}
		shortUsername = username
	} else {
		// Since the username parses as a valid DN, check that it exists and is
		// under a configured base DN in the LDAP directory.
		var isUnderBaseDN bool
		lookupRes, isUnderBaseDN, err = l.GetValidatedUserDN(conn, username)
		if err == nil && !isUnderBaseDN {
			return nil, nil, fmt.Errorf("Unable to find user DN: %w", err)
		}
	}

	groups, err := l.LDAP.SearchForUserGroups(conn, shortUsername, lookupRes.ActualDN)
	if err != nil {
		return nil, nil, err
	}
	return lookupRes, groups, nil
}

// ErrInvalidCredentials is wrapped by the error Bind returns when the username
// does not identify an account or the LDAP server refuses the password.
// Callers must report both cases identically to the client, so that login
// responses cannot be used to enumerate accounts; the wrapped detail is only
// meant for server logs and never contains the password.
var ErrInvalidCredentials = errors.New("invalid LDAP credentials")

// ErrLoginThrottled is returned by Login when the username or the source
// address has too many recent failed logins. It is returned before the
// directory is contacted and does not depend on whether the account exists.
var ErrLoginThrottled = errors.New("too many failed LDAP logins")

// ErrUnusableAccount is wrapped, together with ErrInvalidCredentials, when
// the user search for a username succeeded but did not yield exactly one
// usable entry: several entries match (an ambiguous name, or overlapping
// search bases), or an entry's DN cannot be parsed. Such a username can
// never log in, and the outcome depends on the directory's entries for it,
// so the client gets the same response as for any rejected credentials.
// Login also counts it as a failed attempt, exactly like a wrong password:
// otherwise such a name would be told apart by never being throttled, and
// throttling a name that cannot log in anyway costs nothing.
var ErrUnusableAccount = errors.New("LDAP user search did not yield exactly one usable entry")

// isUserNotFound reports whether err from LookupUsername means that the
// search succeeded but matched no entry, a counted credential failure.
// Account-dependent unusable results, also counted, are recognized by
// isUnusableAccount; every other lookup error (the directory refused or
// failed the search) is a server-side problem that is reported as such and
// is not counted against the username.
func isUserNotFound(err error) bool {
	var lerr *ldap.Error
	if errors.As(err, &lerr) {
		return false
	}
	// minio/pkg documents this prefix for the no-match result and returns
	// it as a plain error, unlike directory errors which are *ldap.Error.
	return strings.HasPrefix(err.Error(), "User DN not found for:")
}

// isUnusableAccount reports whether err from LookupUsername means that the
// search succeeded but its entries for this username are unusable: several
// entries matched, or an entry's DN could not be parsed. Both outcomes are
// plain errors with these documented prefixes in minio/pkg; directory
// errors are returned as *ldap.Error or wrap one under other messages.
func isUnusableAccount(err error) bool {
	msg := err.Error()
	if strings.HasPrefix(msg, "Multiple DNs for ") {
		var lerr *ldap.Error
		return !errors.As(err, &lerr)
	}
	// NormalizeDN of a returned entry: "DN (<dn>) parse failure: ...".
	return strings.HasPrefix(msg, "DN (") && strings.Contains(msg, ") parse failure: ")
}

// decoyBind performs a bind that is certain to fail, against a random entry
// under the first user search base DN. It is used for unknown usernames so
// that they incur the same LDAP round trips as a wrong password for a known
// user. The result is ignored, and conn is closed by the caller right after.
func (l *Config) decoyBind(conn *ldap.Conn, password string) {
	bases := l.LDAP.GetUserDNSearchBaseDistNames()
	if len(bases) == 0 || password == "" {
		return
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return
	}
	dn := fmt.Sprintf("cn=%s,%s", hex.EncodeToString(nonce[:]), bases[0].ServerDN)
	_ = conn.Bind(dn, password)
}

// Bind - binds to ldap, searches LDAP and returns the distinguished name of the
// user and the list of groups. Authentication failures wrap
// ErrInvalidCredentials; any other error means the directory could not be
// queried.
func (l *Config) Bind(username, password string) (*xldap.DNSearchResult, []string, error) {
	if !ValidLoginCredentialLengths(username, password) {
		return nil, nil, fmt.Errorf("%w: username or password exceeds the length limit", ErrInvalidCredentials)
	}
	conn, err := l.LDAP.Connect()
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	// Bind to the lookup user account
	if err = l.LDAP.LookupBind(conn); err != nil {
		return nil, nil, err
	}

	// Lookup user DN
	lookupResult, err := l.LDAP.LookupUsername(conn, username)
	if err != nil {
		switch {
		case isUserNotFound(err):
			// Spend the same bind round trip that a known account
			// costs, so that the response time does not reveal whether
			// it exists.
			l.decoyBind(conn, password)
			return nil, nil, fmt.Errorf("%w: unable to find user DN: %w", ErrInvalidCredentials, err)
		case isUnusableAccount(err):
			// Answered like any rejected credentials, because the
			// result depends on this username's entries.
			l.decoyBind(conn, password)
			return nil, nil, fmt.Errorf("%w: %w: unable to find user DN: %w", ErrInvalidCredentials, ErrUnusableAccount, err)
		default:
			return nil, nil, fmt.Errorf("Unable to find user DN: %w", err)
		}
	}

	// Authenticate the user credentials. Every rejection (wrong password,
	// disabled or locked account, password policy) is reported the same
	// way as an unknown account.
	err = conn.Bind(lookupResult.ActualDN, password)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: LDAP auth failed for DN %s: %w", ErrInvalidCredentials, lookupResult.ActualDN, err)
	}

	// Bind to the lookup user account again to perform group search.
	if err = l.LDAP.LookupBind(conn); err != nil {
		return nil, nil, err
	}

	// User groups lookup.
	groups, err := l.LDAP.SearchForUserGroups(conn, username, lookupResult.ActualDN)
	if err != nil {
		return nil, nil, err
	}

	return lookupResult, groups, nil
}

// Login authenticates username and password for an STS-style login with
// failed-login throttling and a minimum response time for rejections:
//
//   - Over-long credentials are rejected as invalid credentials before the
//     limiter or the directory is involved.
//   - Throttled attempts fail with ErrLoginThrottled without contacting the
//     directory.
//   - Rejected credentials (unknown account, wrong password, refused bind)
//     wrap ErrInvalidCredentials and are counted, as of the time the attempt
//     was reserved. They return no earlier than the configured minimum
//     response time after Login was called, so that the directory's faster
//     rejection of unknown accounts is not visible. The wait happens after
//     the limiter is updated and without holding its lock.
//   - A username whose search yields no single usable entry also wraps
//     ErrInvalidCredentials (and ErrUnusableAccount) and is counted and
//     delayed exactly the same way, so that neither the limiter nor the
//     timing distinguishes it from a wrong password.
//   - Any other error means the directory could not be queried; it is not
//     counted and not delayed.
//
// The delay does not end when ctx is done: a client can cancel the request
// context by half-closing its connection while still reading the response.
// The delay is bounded by the configured minimum response time.
//
// The reservation is released even if the directory call panics.
func (l *Config) Login(ctx context.Context, username, password, sourceIP string) (*xldap.DNSearchResult, []string, error) {
	floor := l.loginFloor
	start := floor.start()
	if !ValidLoginCredentialLengths(username, password) {
		floor.wait(start)
		return nil, nil, fmt.Errorf("%w: username or password exceeds the length limit", ErrInvalidCredentials)
	}
	attempt, ok := l.loginLimiter.Reserve(username, sourceIP)
	if !ok {
		return nil, nil, ErrLoginThrottled
	}
	defer attempt.Abort()

	bind := l.Bind
	if l.bindFn != nil {
		bind = l.bindFn
	}
	lookupResult, groups, err := bind(username, password)
	invalid := errors.Is(err, ErrInvalidCredentials)
	attempt.Finish(invalid)
	if invalid {
		floor.wait(start)
	}
	if err != nil {
		return nil, nil, err
	}
	return lookupResult, groups, nil
}

// GetExpiryDuration - return parsed expiry duration.
func (l Config) GetExpiryDuration(dsecs string) (time.Duration, error) {
	if dsecs == "" {
		return l.stsExpiryDuration, nil
	}

	d, err := strconv.Atoi(dsecs)
	if err != nil {
		return 0, auth.ErrInvalidDuration
	}

	dur := time.Duration(d) * time.Second

	if dur < minLDAPExpiry || dur > maxLDAPExpiry {
		return 0, auth.ErrInvalidDuration
	}
	return dur, nil
}

// ParsesAsDN determines if the given string could be a valid DN based on
// parsing alone.
func (l Config) ParsesAsDN(dn string) bool {
	_, err := ldap.ParseDN(dn)
	return err == nil
}

// IsLDAPUserDN determines if the given string could be a user DN from LDAP.
func (l Config) IsLDAPUserDN(user string) bool {
	udn, err := ldap.ParseDN(user)
	if err != nil {
		return false
	}
	for _, baseDN := range l.LDAP.GetUserDNSearchBaseDistNames() {
		if baseDN.Parsed.AncestorOf(udn) {
			return true
		}
	}
	return false
}

// IsLDAPGroupDN determines if the given string could be a group DN from LDAP.
func (l Config) IsLDAPGroupDN(group string) bool {
	gdn, err := ldap.ParseDN(group)
	if err != nil {
		return false
	}
	for _, baseDN := range l.LDAP.GetGroupSearchBaseDistNames() {
		if baseDN.Parsed.AncestorOf(gdn) {
			return true
		}
	}
	return false
}

// GetNonEligibleUserDistNames - find user accounts (DNs) that are no longer
// present in the LDAP server or do not meet filter criteria anymore
func (l *Config) GetNonEligibleUserDistNames(userDistNames []string) ([]string, error) {
	conn, err := l.LDAP.Connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Bind to the lookup user account
	if err = l.LDAP.LookupBind(conn); err != nil {
		return nil, err
	}

	// Evaluate the filter again with generic wildcard instead of specific values
	filter := strings.ReplaceAll(l.LDAP.UserDNSearchFilter, "%s", "*")

	nonExistentUsers := []string{}
	for _, dn := range userDistNames {
		searchRequest := ldap.NewSearchRequest(
			dn,
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			filter,
			[]string{}, // only need DN, so pass no attributes here
			nil,
		)

		searchResult, err := conn.Search(searchRequest)
		if err != nil {
			// Object does not exist error?
			if ldap.IsErrorWithCode(err, 32) {
				ndn, err := ldap.ParseDN(dn)
				if err != nil {
					return nil, err
				}
				nonExistentUsers = append(nonExistentUsers, ndn.String())
				continue
			}
			return nil, err
		}
		if len(searchResult.Entries) == 0 {
			// DN was not found - this means this user account is
			// expired.
			ndn, err := ldap.ParseDN(dn)
			if err != nil {
				return nil, err
			}
			nonExistentUsers = append(nonExistentUsers, ndn.String())
		}
	}
	return nonExistentUsers, nil
}

// LookupGroupMemberships - for each DN finds the set of LDAP groups they are a
// member of.
func (l *Config) LookupGroupMemberships(userDistNames []string, userDNToUsernameMap map[string]string) (map[string]set.StringSet, error) {
	conn, err := l.LDAP.Connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Bind to the lookup user account
	if err = l.LDAP.LookupBind(conn); err != nil {
		return nil, err
	}

	res := make(map[string]set.StringSet, len(userDistNames))
	for _, userDistName := range userDistNames {
		username := userDNToUsernameMap[userDistName]
		groups, err := l.LDAP.SearchForUserGroups(conn, username, userDistName)
		if err != nil {
			return nil, err
		}
		res[userDistName] = set.CreateStringSet(groups...)
	}

	return res, nil
}

// QuickNormalizeDN - normalizes the given DN without checking if it is valid or
// exists in the LDAP directory. Returns input if error
func (l Config) QuickNormalizeDN(dn string) string {
	if normDN, err := xldap.NormalizeDN(dn); err == nil {
		return normDN
	}
	return dn
}

// DecodeDN - denormalizes the given DN by unescaping any escaped characters.
// Returns input if error
func (l Config) DecodeDN(dn string) string {
	if decodedDN, err := xldap.DecodeDN(dn); err == nil {
		return decodedDN
	}
	return dn
}

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
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	xldap "github.com/minio/pkg/v3/ldap"
)

// fakeDirectory is a minimal LDAP server for tests. Like OpenLDAP's
// back-mdb, it rejects a bind to a DN that does not exist immediately, and
// only spends passwordCost (standing in for an expensive password hash) when
// the entry exists. This reproduces the timing difference between unknown
// accounts and wrong passwords.
type fakeDirectory struct {
	baseDN       string
	lookupDN     string
	lookupPass   string
	passwordCost time.Duration

	mu        sync.Mutex
	users     map[string]fakeUser // uid -> account
	searchErr map[string]uint16   // uid -> result code of the user search
	searchDNS map[string][]string // uid -> entries returned by the user search, overriding users

	conns atomic.Int64 // connections accepted

	ln net.Listener
	wg sync.WaitGroup
}

type fakeUser struct {
	password string
	disabled bool // bind is refused after the password check
}

const (
	fakeBaseDN     = "ou=people,dc=example,dc=org"
	fakeLookupDN   = "cn=lookup,dc=example,dc=org"
	fakeLookupPass = "lookup-secret"
)

func newFakeDirectory(t *testing.T, passwordCost time.Duration) *fakeDirectory {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &fakeDirectory{
		baseDN:       fakeBaseDN,
		lookupDN:     fakeLookupDN,
		lookupPass:   fakeLookupPass,
		passwordCost: passwordCost,
		users:        map[string]fakeUser{},
		searchErr:    map[string]uint16{},
		searchDNS:    map[string][]string{},
		ln:           ln,
	}
	d.wg.Add(1)
	go d.serve()
	t.Cleanup(func() {
		ln.Close()
		d.wg.Wait()
	})
	return d
}

func (d *fakeDirectory) addUser(uid string, u fakeUser) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.users[uid] = u
}

func (d *fakeDirectory) failSearch(uid string, code uint16) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.searchErr[uid] = code
}

// returnEntries makes the user search for uid return entries with the given
// DNs, e.g. several entries (an ambiguous name) or a malformed DN.
func (d *fakeDirectory) returnEntries(uid string, dns ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.searchDNS[uid] = dns
}

func (d *fakeDirectory) userDN(uid string) string { return "uid=" + uid + "," + d.baseDN }

// config returns an LDAP identity configuration that uses this directory,
// validated the same way as at server startup.
func (d *fakeDirectory) config(t *testing.T) *Config {
	t.Helper()
	cfg := &Config{LDAP: xldap.Config{
		Enabled:                  true,
		ServerAddr:               d.ln.Addr().String(),
		ServerInsecure:           true,
		LookupBindDN:             d.lookupDN,
		LookupBindPassword:       d.lookupPass,
		UserDNSearchBaseDistName: d.baseDN,
		UserDNSearchFilter:       "(uid=%s)",
	}}
	if v := cfg.LDAP.Validate(); !v.IsOk() {
		t.Fatalf("fake directory config does not validate: %v", v)
	}
	return cfg
}

func (d *fakeDirectory) serve() {
	defer d.wg.Done()
	var conns sync.WaitGroup
	defer conns.Wait()
	for {
		c, err := d.ln.Accept()
		if err != nil {
			return
		}
		d.conns.Add(1)
		conns.Add(1)
		go func() {
			defer conns.Done()
			d.handle(c)
		}()
	}
}

func (d *fakeDirectory) handle(c net.Conn) {
	defer c.Close()
	for {
		p, err := ber.ReadPacket(c)
		if err != nil || len(p.Children) < 2 {
			return
		}
		msgID, _ := p.Children[0].Value.(int64)
		op := p.Children[1]
		var out []*ber.Packet
		switch op.Tag {
		case ldap.ApplicationBindRequest:
			out = append(out, ldapResult(msgID, ldap.ApplicationBindResponse, d.bind(op)))
		case ldap.ApplicationSearchRequest:
			out = d.search(msgID, op)
		case ldap.ApplicationUnbindRequest:
			return
		default:
			return
		}
		for _, r := range out {
			if _, err := c.Write(r.Bytes()); err != nil {
				return
			}
		}
	}
}

func (d *fakeDirectory) bind(op *ber.Packet) uint16 {
	if len(op.Children) < 3 {
		return ldap.LDAPResultProtocolError
	}
	dn, _ := op.Children[1].Value.(string)
	password := op.Children[2].Data.String()
	if dn == d.lookupDN {
		if password == d.lookupPass {
			return ldap.LDAPResultSuccess
		}
		return ldap.LDAPResultInvalidCredentials
	}
	d.mu.Lock()
	var user *fakeUser
	for uid, u := range d.users {
		if strings.EqualFold(dn, d.userDN(uid)) {
			user = &u
			break
		}
	}
	d.mu.Unlock()
	if user == nil {
		// Unknown entry: refused before any password hashing.
		return ldap.LDAPResultInvalidCredentials
	}
	time.Sleep(d.passwordCost)
	if user.password != password || user.disabled {
		return ldap.LDAPResultInvalidCredentials
	}
	return ldap.LDAPResultSuccess
}

func (d *fakeDirectory) search(msgID int64, op *ber.Packet) []*ber.Packet {
	if len(op.Children) < 7 {
		return []*ber.Packet{ldapResult(msgID, ldap.ApplicationSearchResultDone, ldap.LDAPResultProtocolError)}
	}
	base, _ := op.Children[0].Value.(string)
	scope, _ := op.Children[1].Value.(int64)
	filter, err := ldap.DecompileFilter(op.Children[6])
	if err != nil {
		return []*ber.Packet{ldapResult(msgID, ldap.ApplicationSearchResultDone, ldap.LDAPResultProtocolError)}
	}
	done := func(code uint16) *ber.Packet { return ldapResult(msgID, ldap.ApplicationSearchResultDone, code) }
	if !strings.EqualFold(base, d.baseDN) {
		return []*ber.Packet{done(ldap.LDAPResultNoSuchObject)}
	}
	if scope == int64(ldap.ScopeBaseObject) {
		return []*ber.Packet{searchEntry(msgID, d.baseDN), done(ldap.LDAPResultSuccess)}
	}
	uid := strings.TrimSuffix(strings.TrimPrefix(filter, "(uid="), ")")
	d.mu.Lock()
	code, failing := d.searchErr[uid]
	_, exists := d.users[uid]
	dns, override := d.searchDNS[uid]
	d.mu.Unlock()
	if failing {
		return []*ber.Packet{done(code)}
	}
	if override {
		out := make([]*ber.Packet, 0, len(dns)+1)
		for _, dn := range dns {
			out = append(out, searchEntry(msgID, dn))
		}
		return append(out, done(ldap.LDAPResultSuccess))
	}
	if exists {
		return []*ber.Packet{searchEntry(msgID, d.userDN(uid)), done(ldap.LDAPResultSuccess)}
	}
	return []*ber.Packet{done(ldap.LDAPResultSuccess)}
}

func ldapEnvelope(msgID int64, op *ber.Packet) *ber.Packet {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "MessageID"))
	env.AppendChild(op)
	return env
}

func ldapResult(msgID int64, tag ber.Tag, code uint16) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "Result")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), "resultCode"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	return ldapEnvelope(msgID, op)
}

func searchEntry(msgID int64, dn string) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "Search Result Entry")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "objectName"))
	op.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes"))
	return ldapEnvelope(msgID, op)
}

// TestFakeDirectorySanity checks the fake server against the real Bind path.
func TestFakeDirectorySanity(t *testing.T) {
	d := newFakeDirectory(t, 0)
	d.addUser("alice", fakeUser{password: "alice-pass"})
	cfg := d.config(t)
	res, _, err := cfg.Bind("alice", "alice-pass")
	if err != nil {
		t.Fatalf("expected successful bind, got %v", err)
	}
	if res.ActualDN != d.userDN("alice") {
		t.Fatalf("unexpected DN %q", res.ActualDN)
	}
	if _, _, err := cfg.Bind("alice", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials for a wrong password, got %v", err)
	}
	if _, _, err := cfg.Bind("nobody", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected invalid credentials for an unknown user, got %v", err)
	}
}

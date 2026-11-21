// Copyright (c) 2015-2021 MinIO, Inc.
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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sort"
	"strconv"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/pkg/v3/ldap"
	"github.com/relvo-labs/granary/internal/config"
	"github.com/relvo-labs/granary/internal/crypto"
)

const (
	defaultLDAPExpiry = time.Hour * 1

	minLDAPExpiry time.Duration = 15 * time.Minute
	maxLDAPExpiry time.Duration = 365 * 24 * time.Hour
)

// Config contains AD/LDAP server connectivity information.
type Config struct {
	LDAP ldap.Config

	stsExpiryDuration time.Duration // contains converted value

	// loginLimiter throttles repeated failed logins; shared by clones so
	// that copies of the active configuration count failures together.
	loginLimiter *LoginFailureLimiter
}

// LoginLimiter returns the failed-login limiter for this configuration. The
// result may be nil, which disables throttling.
func (l *Config) LoginLimiter() *LoginFailureLimiter {
	if l == nil {
		return nil
	}
	return l.loginLimiter
}

// Enabled returns if LDAP is enabled.
func (l *Config) Enabled() bool {
	return l.LDAP.Enabled
}

// Clone returns a cloned copy of LDAP config.
func (l *Config) Clone() Config {
	if l == nil {
		return Config{}
	}
	cfg := Config{
		LDAP:              l.LDAP.Clone(),
		stsExpiryDuration: l.stsExpiryDuration,
		loginLimiter:      l.loginLimiter,
	}
	return cfg
}

// LDAP keys and envs.
const (
	ServerAddr         = "server_addr"
	SRVRecordName      = "srv_record_name"
	LookupBindDN       = "lookup_bind_dn"
	LookupBindPassword = "lookup_bind_password"
	UserDNSearchBaseDN = "user_dn_search_base_dn"
	UserDNSearchFilter = "user_dn_search_filter"
	UserDNAttributes   = "user_dn_attributes"
	GroupSearchFilter  = "group_search_filter"
	GroupSearchBaseDN  = "group_search_base_dn"
	TLSSkipVerify      = "tls_skip_verify"
	ServerInsecure     = "server_insecure"
	ServerStartTLS     = "server_starttls"

	LoginFailureUserLimit = "login_failure_user_limit"
	LoginFailureIPLimit   = "login_failure_ip_limit"
	LoginFailureWindow    = "login_failure_window"

	EnvServerAddr         = "MINIO_IDENTITY_LDAP_SERVER_ADDR"
	EnvSRVRecordName      = "MINIO_IDENTITY_LDAP_SRV_RECORD_NAME"
	EnvTLSSkipVerify      = "MINIO_IDENTITY_LDAP_TLS_SKIP_VERIFY"
	EnvServerInsecure     = "MINIO_IDENTITY_LDAP_SERVER_INSECURE"
	EnvServerStartTLS     = "MINIO_IDENTITY_LDAP_SERVER_STARTTLS"
	EnvUsernameFormat     = "MINIO_IDENTITY_LDAP_USERNAME_FORMAT"
	EnvUserDNSearchBaseDN = "MINIO_IDENTITY_LDAP_USER_DN_SEARCH_BASE_DN"
	EnvUserDNSearchFilter = "MINIO_IDENTITY_LDAP_USER_DN_SEARCH_FILTER"
	EnvUserDNAttributes   = "MINIO_IDENTITY_LDAP_USER_DN_ATTRIBUTES"
	EnvGroupSearchFilter  = "MINIO_IDENTITY_LDAP_GROUP_SEARCH_FILTER"
	EnvGroupSearchBaseDN  = "MINIO_IDENTITY_LDAP_GROUP_SEARCH_BASE_DN"
	EnvLookupBindDN       = "MINIO_IDENTITY_LDAP_LOOKUP_BIND_DN"
	EnvLookupBindPassword = "MINIO_IDENTITY_LDAP_LOOKUP_BIND_PASSWORD"

	EnvLoginFailureUserLimit = "MINIO_IDENTITY_LDAP_LOGIN_FAILURE_USER_LIMIT"
	EnvLoginFailureIPLimit   = "MINIO_IDENTITY_LDAP_LOGIN_FAILURE_IP_LIMIT"
	EnvLoginFailureWindow    = "MINIO_IDENTITY_LDAP_LOGIN_FAILURE_WINDOW"
)

var removedKeys = []string{
	"sts_expiry",
	"username_format",
	"username_search_filter",
	"username_search_base_dn",
	"group_name_attribute",
}

// DefaultKVS - default config for LDAP config
var (
	DefaultKVS = config.KVS{
		config.KV{
			Key:   config.Enable,
			Value: "",
		},
		config.KV{
			Key:   ServerAddr,
			Value: "",
		},
		config.KV{
			Key:   SRVRecordName,
			Value: "",
		},
		config.KV{
			Key:   UserDNSearchBaseDN,
			Value: "",
		},
		config.KV{
			Key:   UserDNSearchFilter,
			Value: "",
		},
		config.KV{
			Key:   UserDNAttributes,
			Value: "",
		},
		config.KV{
			Key:   GroupSearchFilter,
			Value: "",
		},
		config.KV{
			Key:   GroupSearchBaseDN,
			Value: "",
		},
		config.KV{
			Key:   TLSSkipVerify,
			Value: config.EnableOff,
		},
		config.KV{
			Key:   ServerInsecure,
			Value: config.EnableOff,
		},
		config.KV{
			Key:   ServerStartTLS,
			Value: config.EnableOff,
		},
		config.KV{
			Key:   LookupBindDN,
			Value: "",
		},
		config.KV{
			Key:   LookupBindPassword,
			Value: "",
		},
		config.KV{
			Key:   LoginFailureUserLimit,
			Value: strconv.Itoa(DefaultLoginFailureUserLimit),
		},
		config.KV{
			Key:   LoginFailureIPLimit,
			Value: strconv.Itoa(DefaultLoginFailureIPLimit),
		},
		config.KV{
			Key:   LoginFailureWindow,
			Value: DefaultLoginFailureWindow.String(),
		},
	}
)

// Enabled returns if LDAP config is enabled.
func Enabled(kvs config.KVS) bool {
	return kvs.Get(ServerAddr) != ""
}

// Lookup - initializes LDAP config, overrides config, if any ENV values are set.
func Lookup(s config.Config, rootCAs *x509.CertPool) (l Config, err error) {
	l = Config{}

	// Purge all removed keys first
	kvs := s[config.IdentityLDAPSubSys][config.Default]
	if len(kvs) > 0 {
		for _, k := range removedKeys {
			kvs.Delete(k)
		}
		s[config.IdentityLDAPSubSys][config.Default] = kvs
	}

	if err := s.CheckValidKeys(config.IdentityLDAPSubSys, removedKeys); err != nil {
		return l, err
	}

	getCfgVal := func(cfgParam string) string {
		// As parameters are already validated, we skip checking
		// if the config param was found.
		val, _, _ := s.ResolveConfigParam(config.IdentityLDAPSubSys, config.Default, cfgParam, false)
		return val
	}

	ldapServer := getCfgVal(ServerAddr)
	if ldapServer == "" {
		return l, nil
	}

	// Set ServerName in TLS config for proper certificate validation
	host, _, err := net.SplitHostPort(ldapServer)
	if err != nil {
		host = ldapServer
	}

	l.LDAP = ldap.Config{
		ServerAddr:    ldapServer,
		SRVRecordName: getCfgVal(SRVRecordName),
		TLS: &tls.Config{
			ServerName:         host,
			MinVersion:         tls.VersionTLS12,
			NextProtos:         []string{"h2", "http/1.1"},
			ClientSessionCache: tls.NewLRUClientSessionCache(100),
			CipherSuites:       crypto.TLSCiphersBackwardCompatible(), // Contains RSA key exchange
			RootCAs:            rootCAs,
		},
	}

	// Parse explicitly set enable=on/off flag.
	isEnableFlagExplicitlySet := false
	if v := getCfgVal(config.Enable); v != "" {
		isEnableFlagExplicitlySet = true
		l.LDAP.Enabled, err = config.ParseBool(v)
		if err != nil {
			return l, err
		}
	}

	l.stsExpiryDuration = defaultLDAPExpiry

	// LDAP connection configuration
	if v := getCfgVal(ServerInsecure); v != "" {
		l.LDAP.ServerInsecure, err = config.ParseBool(v)
		if err != nil {
			return l, err
		}
	}
	if v := getCfgVal(ServerStartTLS); v != "" {
		l.LDAP.ServerStartTLS, err = config.ParseBool(v)
		if err != nil {
			return l, err
		}
	}
	if v := getCfgVal(TLSSkipVerify); v != "" {
		l.LDAP.TLS.InsecureSkipVerify, err = config.ParseBool(v)
		if err != nil {
			return l, err
		}
	}

	// Lookup bind user configuration
	l.LDAP.LookupBindDN = getCfgVal(LookupBindDN)
	l.LDAP.LookupBindPassword = getCfgVal(LookupBindPassword)

	// User DN search configuration
	l.LDAP.UserDNSearchFilter = getCfgVal(UserDNSearchFilter)
	l.LDAP.UserDNSearchBaseDistName = getCfgVal(UserDNSearchBaseDN)
	l.LDAP.UserDNAttributes = getCfgVal(UserDNAttributes)

	// Group search params configuration
	l.LDAP.GroupSearchFilter = getCfgVal(GroupSearchFilter)
	l.LDAP.GroupSearchBaseDistName = getCfgVal(GroupSearchBaseDN)

	// Failed login throttling configuration
	limitCfg, err := lookupLoginLimitConfig(getCfgVal)
	if err != nil {
		return l, err
	}
	l.loginLimiter = NewLoginFailureLimiter(limitCfg)

	// If enable flag was not explicitly set, we treat it as implicitly set at
	// this point as necessary configuration is available.
	if !isEnableFlagExplicitlySet && !l.LDAP.Enabled {
		l.LDAP.Enabled = true
	}
	// Validate and test configuration.
	valResult := l.LDAP.Validate()
	if !valResult.IsOk() {
		// Set to false if configuration fails to validate.
		l.LDAP.Enabled = false
		return l, valResult
	}

	return l, nil
}

// GetConfigList - returns a list of LDAP configurations.
func (l *Config) GetConfigList(s config.Config) ([]madmin.IDPListItem, error) {
	ldapConfigs, err := s.GetAvailableTargets(config.IdentityLDAPSubSys)
	if err != nil {
		return nil, err
	}

	// For now, ldapConfigs will only have a single entry for the default
	// configuration.

	var res []madmin.IDPListItem
	for _, cfg := range ldapConfigs {
		res = append(res, madmin.IDPListItem{
			Type:    "ldap",
			Name:    cfg,
			Enabled: l.Enabled(),
		})
	}

	return res, nil
}

// ErrProviderConfigNotFound - represents a non-existing provider error.
var ErrProviderConfigNotFound = errors.New("provider configuration not found")

// GetConfigInfo - returns config details for an LDAP configuration.
func (l *Config) GetConfigInfo(s config.Config, cfgName string) ([]madmin.IDPCfgInfo, error) {
	// For now only a single LDAP config is supported.
	if cfgName != madmin.Default {
		return nil, ErrProviderConfigNotFound
	}
	kvsrcs, err := s.GetResolvedConfigParams(config.IdentityLDAPSubSys, cfgName, true)
	if err != nil {
		return nil, err
	}

	res := make([]madmin.IDPCfgInfo, 0, len(kvsrcs))
	for _, kvsrc := range kvsrcs {
		// skip default values.
		if kvsrc.Src == config.ValueSourceDef {
			continue
		}
		res = append(res, madmin.IDPCfgInfo{
			Key:   kvsrc.Key,
			Value: kvsrc.Value,
			IsCfg: true,
			IsEnv: kvsrc.Src == config.ValueSourceEnv,
		})
	}

	// sort the structs by the key
	sort.Slice(res, func(i, j int) bool {
		return res[i].Key < res[j].Key
	})

	return res, nil
}

// lookupLoginLimitConfig parses the failed-login throttling settings. Empty
// values select the defaults; a limit of 0 disables that dimension.
func lookupLoginLimitConfig(getCfgVal func(string) string) (LoginLimitConfig, error) {
	cfg := LoginLimitConfig{
		UserLimit:  DefaultLoginFailureUserLimit,
		IPLimit:    DefaultLoginFailureIPLimit,
		Window:     DefaultLoginFailureWindow,
		MaxEntries: DefaultLoginFailureMaxEntries,
	}
	parseLimit := func(key string, dst *int) error {
		v := getCfgVal(key)
		if v == "" {
			return nil
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return config.Errorf("invalid %s value %q: must be a non-negative integer", key, v)
		}
		*dst = n
		return nil
	}
	if err := parseLimit(LoginFailureUserLimit, &cfg.UserLimit); err != nil {
		return cfg, err
	}
	if err := parseLimit(LoginFailureIPLimit, &cfg.IPLimit); err != nil {
		return cfg, err
	}
	if v := getCfgVal(LoginFailureWindow); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return cfg, config.Errorf("invalid %s value %q: must be a positive duration such as 15m", LoginFailureWindow, v)
		}
		cfg.Window = d
	}
	return cfg, nil
}

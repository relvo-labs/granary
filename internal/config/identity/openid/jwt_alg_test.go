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

package openid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v4"
	xnet "github.com/minio/pkg/v3/net"
	"github.com/relvo-labs/granary/internal/arn"
)

// Regression tests for CVE-2026-33322 / GHSA-5cx5-wh4m-82fh (issue #70):
// OpenID tokens must only verify with an asymmetric key published by the
// provider's JWKS, using an algorithm that matches that key's type.

const (
	algTestClientID     = "granary-test-client"
	algTestClientSecret = "granary-test-client-secret"
	algTestRSAKid       = "rsa-test-kid"
	algTestECKid        = "ec-test-kid"
)

type algTestIDP struct {
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
	server *httptest.Server
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newAlgTestIDP(t *testing.T) *algTestIDP {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks := map[string]any{
		"keys": []map[string]string{
			{
				"kty": "RSA",
				"kid": algTestRSAKid,
				"alg": "RS256",
				"use": "sig",
				"n":   b64url(rsaKey.N.Bytes()),
				"e":   b64url(big.NewInt(int64(rsaKey.E)).Bytes()),
			},
			{
				"kty": "EC",
				"kid": algTestECKid,
				"alg": "ES256",
				"use": "sig",
				"crv": "P-256",
				"x":   b64url(ecKey.X.FillBytes(make([]byte, 32))),
				"y":   b64url(ecKey.Y.FillBytes(make([]byte, 32))),
			},
		},
	}
	body, err := json.Marshal(jwks)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(server.Close)
	return &algTestIDP{rsaKey: rsaKey, ecKey: ecKey, server: server}
}

// config returns an OpenID config for the test IDP. When populate is true the
// JWKS is loaded up-front exactly as LookupConfig does at server start;
// otherwise the keys are only fetched by Validate's refresh-and-retry path.
func (idp *algTestIDP) config(t *testing.T, populate bool) *Config {
	t.Helper()
	u, err := xnet.ParseHTTPURL(idp.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	provider := providerCfg{
		ClientID:     algTestClientID,
		ClientSecret: algTestClientSecret,
	}
	provider.JWKS.URL = u
	cfg := &Config{
		Enabled: true,
		pubKeys: publicKeys{
			RWMutex: &sync.RWMutex{},
			pkMap:   map[string]any{},
		},
		arnProviderCfgsMap: map[arn.ARN]*providerCfg{
			DummyRoleARN: &provider,
		},
		ProviderCfgs: map[string]*providerCfg{
			"1": &provider,
		},
		closeRespFn: func(rc io.ReadCloser) {
			rc.Close()
		},
	}
	if populate {
		if err := cfg.PopulatePublicKey(DummyRoleARN); err != nil {
			t.Fatal(err)
		}
	}
	return cfg
}

func algTestClaims() jwtgo.MapClaims {
	return jwtgo.MapClaims{
		"sub":   "attacker-chosen-identity",
		"aud":   algTestClientID,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"email": "admin@example.invalid",
	}
}

func signToken(t *testing.T, method jwtgo.SigningMethod, kid string, key any) string {
	t.Helper()
	tok := jwtgo.NewWithClaims(method, algTestClaims())
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// unsignedToken builds a token with an arbitrary header and an empty or
// caller-supplied signature segment, bypassing the library's signer.
func unsignedToken(t *testing.T, header map[string]any, sig string) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	c, err := json.Marshal(algTestClaims())
	if err != nil {
		t.Fatal(err)
	}
	return b64url(h) + "." + b64url(c) + "." + sig
}

func TestValidateRejectsSymmetricAndMismatchedAlgorithms(t *testing.T) {
	idp := newAlgTestIDP(t)

	rsaPubDER, err := x509.MarshalPKIXPublicKey(&idp.rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaPubDER})
	secret := []byte(algTestClientSecret)

	testCases := []struct {
		name  string
		token func(t *testing.T) string
	}{
		{"HS256 signed with client secret, kid=client_id", func(t *testing.T) string {
			return signToken(t, jwtgo.SigningMethodHS256, algTestClientID, secret)
		}},
		{"HS384 signed with client secret, kid=client_id", func(t *testing.T) string {
			return signToken(t, jwtgo.SigningMethodHS384, algTestClientID, secret)
		}},
		{"HS512 signed with client secret, kid=client_id", func(t *testing.T) string {
			return signToken(t, jwtgo.SigningMethodHS512, algTestClientID, secret)
		}},
		{"HS256 signed with client secret, kid=RSA JWKS kid", func(t *testing.T) string {
			return signToken(t, jwtgo.SigningMethodHS256, algTestRSAKid, secret)
		}},
		{"HS256 signed with client secret, no kid", func(t *testing.T) string {
			return signToken(t, jwtgo.SigningMethodHS256, "", secret)
		}},
		{"HS256 signed with RSA public key PEM, kid=RSA JWKS kid", func(t *testing.T) string {
			return signToken(t, jwtgo.SigningMethodHS256, algTestRSAKid, rsaPubPEM)
		}},
		{"HS256 signed with RSA public key DER, kid=RSA JWKS kid", func(t *testing.T) string {
			return signToken(t, jwtgo.SigningMethodHS256, algTestRSAKid, rsaPubDER)
		}},
		{"HS256 signed with RSA modulus, kid=RSA JWKS kid", func(t *testing.T) string {
			return signToken(t, jwtgo.SigningMethodHS256, algTestRSAKid, idp.rsaKey.N.Bytes())
		}},
		{"alg=none, kid=client_id", func(t *testing.T) string {
			return unsignedToken(t, map[string]any{"alg": "none", "typ": "JWT", "kid": algTestClientID}, "")
		}},
		{"alg=none, kid=RSA JWKS kid", func(t *testing.T) string {
			return unsignedToken(t, map[string]any{"alg": "none", "typ": "JWT", "kid": algTestRSAKid}, "")
		}},
		{"alg=RS256 with kid of EC JWKS key", func(t *testing.T) string {
			return signToken(t, jwtgo.SigningMethodRS256, algTestECKid, idp.rsaKey)
		}},
		{"alg=ES256 with kid of RSA JWKS key", func(t *testing.T) string {
			return signToken(t, jwtgo.SigningMethodES256, algTestRSAKid, idp.ecKey)
		}},
		{"RS256 signed by a key not in the JWKS", func(t *testing.T) string {
			other, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			return signToken(t, jwtgo.SigningMethodRS256, algTestRSAKid, other)
		}},
	}

	for _, populate := range []bool{true, false} {
		path := "jwks-preloaded"
		if !populate {
			path = "jwks-refresh-retry"
		}
		for _, tc := range testCases {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				cfg := idp.config(t, populate)
				token := tc.token(t)
				claims := map[string]any{}
				if err := cfg.Validate(t.Context(), DummyRoleARN, token, "", "", claims); err == nil {
					t.Fatalf("forged token was accepted; claims=%v", claims)
				}
			})
		}
	}
}

func TestValidateAcceptsJWKSAsymmetricAlgorithms(t *testing.T) {
	idp := newAlgTestIDP(t)

	testCases := []struct {
		name   string
		method jwtgo.SigningMethod
		kid    string
		key    any
	}{
		{"RS256", jwtgo.SigningMethodRS256, algTestRSAKid, idp.rsaKey},
		{"RS512", jwtgo.SigningMethodRS512, algTestRSAKid, idp.rsaKey},
		{"RS3256", SigningMethodRS3256, algTestRSAKid, idp.rsaKey},
		{"ES256", jwtgo.SigningMethodES256, algTestECKid, idp.ecKey},
	}

	for _, populate := range []bool{true, false} {
		path := "jwks-preloaded"
		if !populate {
			path = "jwks-refresh-retry"
		}
		for _, tc := range testCases {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				cfg := idp.config(t, populate)
				token := signToken(t, tc.method, tc.kid, tc.key)
				claims := map[string]any{}
				if err := cfg.Validate(t.Context(), DummyRoleARN, token, "", "", claims); err != nil {
					t.Fatalf("valid %s token rejected: %v", tc.name, err)
				}
				if claims["sub"] != "attacker-chosen-identity" {
					t.Fatalf("unexpected claims %v", claims)
				}
			})
		}
	}
}

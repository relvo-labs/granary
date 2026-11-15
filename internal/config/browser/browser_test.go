// Copyright (c) 2015-2023 MinIO, Inc.
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

package browser

import (
	"strings"
	"testing"

	"github.com/relvo-labs/granary/internal/config"
)

func TestLookupConfigCSPPolicy(t *testing.T) {
	for _, key := range []string{
		EnvBrowserCSPPolicy, EnvBrowserHSTSSeconds, EnvBrowserHSTSIncludeSubdomains,
		EnvBrowserHSTSPreload, EnvBrowserReferrerPolicy,
	} {
		t.Setenv(key, "")
	}

	const defaultPolicy = "default-src 'self' 'unsafe-eval' 'unsafe-inline'; script-src 'self' https://unpkg.com;  connect-src 'self' https://unpkg.com; img-src 'self' data: blob:;"
	const storedPolicy = "default-src 'none';  img-src https://stored.example.test;"
	const envPolicy = "default-src 'self'; img-src https://env.example.test data:;  connect-src 'none';"

	tests := []struct {
		name      string
		kvs       config.KVS
		envPolicy string
		want      string
	}{
		{name: "missing config", want: defaultPolicy},
		{name: "default config", kvs: DefaultKVS, want: defaultPolicy},
		{name: "empty stored policy", kvs: config.KVS{{Key: browserCSPPolicy}}, want: defaultPolicy},
		{name: "stored policy", kvs: config.KVS{{Key: browserCSPPolicy, Value: storedPolicy}}, want: storedPolicy},
		{name: "environment policy", kvs: DefaultKVS, envPolicy: envPolicy, want: envPolicy},
		{name: "environment overrides stored policy", kvs: config.KVS{{Key: browserCSPPolicy, Value: storedPolicy}}, envPolicy: envPolicy, want: envPolicy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvBrowserCSPPolicy, tt.envPolicy)
			cfg, err := LookupConfig(tt.kvs)
			if err != nil {
				t.Fatal(err)
			}
			got := cfg.GetCSPolicy()
			if got != tt.want {
				t.Fatalf("CSP policy = %q, want %q", got, tt.want)
			}
			if tt.want == defaultPolicy && !strings.Contains(got, "img-src 'self' data: blob:;") {
				t.Fatalf("default CSP missing image directive: %q", got)
			}
		})
	}
}

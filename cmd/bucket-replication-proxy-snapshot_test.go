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

package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/minio/madmin-go/v3"
	xnet "github.com/minio/pkg/v3/net"
	"github.com/minio/pkg/v3/policy"
	"github.com/relvo-labs/granary/internal/auth"
	polplugin "github.com/relvo-labs/granary/internal/config/policy/plugin"
	xhttp "github.com/relvo-labs/granary/internal/http"
)

func TestAPITaggingProxyResponderSnapshot(t *testing.T) {
	t.Cleanup(resetTestGlobals)
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testAPITaggingProxyResponderSnapshot})
}

func testAPITaggingProxyResponderSnapshot(_ ObjectLayer, instanceType, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
	user := newTaggingTestUser(t)
	for _, policyType := range []string{"deny", "allow"} {
		for _, tc := range []struct {
			name, initial, missing, replace string
		}{
			{name: "offline-recovers", initial: "offline"},
			{name: "clientless-recovers", initial: "clientless"},
			{name: "disabled-recovers", initial: "disabled"},
			{name: "not-found-key", missing: "NoSuchKey"},
			{name: "not-found-version", missing: "NoSuchVersion"},
			{name: "client-replaced", initial: "offline", replace: "client"},
			{name: "bucket-replaced", initial: "offline", replace: "bucket"},
			{name: "agreeing"},
		} {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/%s/reverse=%t", instanceType, policyType, tc.name, reverse), func(t *testing.T) {
					var primaryReads, secondaryReads, primaryDeletes, secondaryDeletes, wrongBucket, authorizations atomic.Int32
					byHost := make(map[string]bool)
					targets := installTaggingProxyTargets(t, bucket, []string{"active", "active"}, func(w http.ResponseWriter, r *http.Request) {
						primary := byHost[r.Host]
						if r.URL.Path != "/remote-bucket/snapshot" {
							wrongBucket.Add(1)
						}
						if !r.URL.Query().Has("tagging") {
							t.Error("unexpected non-tagging request")
						}
						switch r.Method {
						case http.MethodGet:
							if primary {
								primaryReads.Add(1)
							} else {
								secondaryReads.Add(1)
								if tc.missing != "" {
									writeProxyTaggingError(w, tc.missing, http.StatusNotFound)
									return
								}
							}
							value := "allowed"
							if !primary && tc.name != "agreeing" {
								value = "denied"
							}
							fmt.Fprintf(w, "<Tagging><TagSet><Tag><Key>test</Key><Value>%s</Value></Tag></TagSet></Tagging>", value)
						case http.MethodDelete:
							if primary {
								primaryDeletes.Add(1)
							} else {
								secondaryDeletes.Add(1)
							}
							w.WriteHeader(http.StatusNoContent)
						default:
							t.Error("unexpected remote method")
							w.WriteHeader(http.StatusMethodNotAllowed)
						}
					})
					sys := globalBucketTargetSys
					primaryARN, secondaryARN := targets.Targets[0].Arn, targets.Targets[1].Arn
					primary := sys.GetRemoteTargetClient(bucket, primaryARN)
					secondary := sys.GetRemoteTargetClient(bucket, secondaryARN)
					byHost[primary.EndpointURL().Host] = true
					byHost[secondary.EndpointURL().Host] = false
					switch tc.initial {
					case "offline":
						sys.markOffline(secondary.EndpointURL())
					case "clientless":
						sys.Lock()
						sys.arnRemotesMap[secondaryARN] = arnTarget{lastRefresh: UTCNow()}
						sys.Unlock()
					case "disabled":
						disabled := *secondary
						disabled.disableProxy = true
						sys.Lock()
						sys.arnRemotesMap[secondaryARN] = arnTarget{Client: &disabled}
						sys.Unlock()
					}
					ordered := &madmin.BucketTargets{Targets: append([]madmin.BucketTarget(nil), targets.Targets...)}
					if reverse {
						ordered.Targets[0], ordered.Targets[1] = ordered.Targets[1], ordered.Targets[0]
					}
					setTaggingProxyConfig(t, bucket, ordered)
					statements := fmt.Sprintf(`{"Effect":"Allow","Action":"s3:DeleteObjectTagging","Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"allowed"}}}`, bucket)
					if policyType == "deny" {
						statements = fmt.Sprintf(`{"Effect":"Allow","Action":"s3:DeleteObjectTagging","Resource":"arn:aws:s3:::%s/*"},{"Effect":"Deny","Action":"s3:DeleteObjectTagging","Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"denied"}}}`, bucket, bucket)
					}
					setTaggingTestPolicy(t, bucket, user, statements)
					version := ""
					if tc.missing == "NoSuchVersion" {
						version = "a3348c34-c352-4498-82f0-1098e8b34df9"
					}
					// Explicit target orders exercise eligibility and not-found
					// aggregation without relying on configuration-map ordering.
					got, result := proxyGetTaggingToRepTarget(t.Context(), bucket, "snapshot", ObjectOptions{VersionID: version}, ordered)
					if result.Err != nil || !result.Proxy || got == nil || got.String() != "test=allowed" {
						t.Fatal("eligible responders did not provide the allowed tags")
					}
					primaryReads.Store(0)
					secondaryReads.Store(0)
					compiled := globalIAMSys.GetCombinedPolicy("tagging-test-policy")
					// The real authorization plugin interface gives a deterministic
					// barrier after all reads and before the DELETE mutation.
					// Evaluate the actual IAM policy, then recover/reconfigure
					// targets before returning its authorization decision.
					gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						var input struct {
							Input policy.Args `json:"input"`
						}
						if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
							t.Error(err)
							w.WriteHeader(http.StatusBadRequest)
							return
						}
						authorizations.Add(1)
						wantSecondaryReads := int32(0)
						if tc.missing != "" || tc.name == "agreeing" {
							wantSecondaryReads = 1
						}
						if primaryReads.Load() != 1 || secondaryReads.Load() != wantSecondaryReads {
							t.Errorf("reads before authorization = %d/%d, want 1/%d", primaryReads.Load(), secondaryReads.Load(), wantSecondaryReads)
						}
						allowed := compiled.IsAllowed(input.Input)
						if !allowed {
							t.Error("policy did not authorize the successful responders' tags")
						}
						sys.hMutex.Lock()
						health := sys.hc[secondary.EndpointURL().Host]
						health.Online = true
						sys.hc[secondary.EndpointURL().Host] = health
						sys.hMutex.Unlock()
						sys.Lock()
						sys.arnRemotesMap[secondaryARN] = arnTarget{Client: secondary}
						switch tc.replace {
						case "client":
							sys.arnRemotesMap[primaryARN] = arnTarget{Client: secondary}
						case "bucket":
							sys.arnRemotesMap[primaryARN] = arnTarget{Client: &TargetClient{Client: primary.Client, Bucket: "different-bucket"}}
						}
						sys.Unlock()
						fmt.Fprintf(w, `{"result":%t}`, allowed)
					}))
					t.Cleanup(gate.Close)
					endpoint, err := xnet.ParseHTTPURL(gate.URL)
					if err != nil {
						t.Fatal(err)
					}
					previous := newGlobalAuthZPluginFn()
					setGlobalAuthZPlugin(polplugin.New(polplugin.Args{
						URL: endpoint, Transport: gate.Client().Transport,
						CloseRespFn: func(body io.ReadCloser) { body.Close() },
					}))
					t.Cleanup(func() { setGlobalAuthZPlugin(previous) })
					target := getGetObjectURL("", bucket, "snapshot") + "?tagging"
					if version != "" {
						target += "&versionId=" + version
					}
					rec := taggingTestRequest(t, router, http.MethodDelete, target, "", user)
					if rec.Code != http.StatusNoContent || rec.Header().Get(xhttp.MinIOTaggingProxied) != "true" {
						t.Errorf("HTTP %d, want proxied HTTP 204", rec.Code)
					}
					wantSecondaryDeletes := int32(0)
					if tc.name == "agreeing" {
						wantSecondaryDeletes = 1
					}
					if primaryDeletes.Load() != 1 || secondaryDeletes.Load() != wantSecondaryDeletes || wrongBucket.Load() != 0 {
						t.Errorf("deletes primary/secondary/wrong-bucket = %d/%d/%d, want 1/%d/0", primaryDeletes.Load(), secondaryDeletes.Load(), wrongBucket.Load(), wantSecondaryDeletes)
					}
					if authorizations.Load() != 1 {
						t.Errorf("authorization calls = %d, want 1", authorizations.Load())
					}
				})
			}
		}
	}
}

// Exercise the entire read/mutate sequence with literal target-list orders.
// The API test above supplies the authorization barrier independently of the
// order chosen by getProxyTargets' configuration map.
func TestProxyDeleteTaggingResponderSnapshot(t *testing.T) {
	for _, missing := range []string{"offline", "NoSuchKey", "NoSuchVersion"} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reverse=%t", missing, reverse), func(t *testing.T) {
				const bucket = "snapshot-bucket"
				var unreadHost string
				var readDeletes, unreadDeletes atomic.Int32
				targets := installTaggingProxyTargets(t, bucket, []string{"active", "active"}, func(w http.ResponseWriter, r *http.Request) {
					unread := r.Host == unreadHost
					switch r.Method {
					case http.MethodGet:
						if unread {
							writeProxyTaggingError(w, missing, http.StatusNotFound)
							return
						}
						fmt.Fprint(w, "<Tagging><TagSet><Tag><Key>test</Key><Value>allowed</Value></Tag></TagSet></Tagging>")
					case http.MethodDelete:
						if unread {
							unreadDeletes.Add(1)
						} else {
							readDeletes.Add(1)
						}
						w.WriteHeader(http.StatusNoContent)
					default:
						t.Error("unexpected remote method")
					}
				})
				sys := globalBucketTargetSys
				unread := sys.GetRemoteTargetClient(bucket, targets.Targets[1].Arn)
				unreadHost = unread.EndpointURL().Host
				if missing == "offline" {
					sys.markOffline(unread.EndpointURL())
				}
				if reverse {
					targets.Targets[0], targets.Targets[1] = targets.Targets[1], targets.Targets[0]
				}
				opts := ObjectOptions{}
				if missing == "NoSuchVersion" {
					opts.VersionID = "a3348c34-c352-4498-82f0-1098e8b34df9"
				}
				got, result := proxyGetTaggingToRepTarget(t.Context(), bucket, "snapshot", opts, targets)
				if result.Err != nil || !result.Proxy || got == nil || got.String() != "test=allowed" {
					t.Fatal("successful responder did not provide the authorized tags")
				}
				// Recover the unread target only after the read has completed.
				sys.hMutex.Lock()
				health := sys.hc[unreadHost]
				health.Online = true
				sys.hc[unreadHost] = health
				sys.hMutex.Unlock()
				result = proxyDeleteTaggingToRepTarget(t.Context(), "snapshot", opts, result.taggingTargets)
				if result.Err != nil || !result.Proxy {
					t.Fatalf("delete result = %+v", result)
				}
				if readDeletes.Load() != 1 || unreadDeletes.Load() != 0 {
					t.Errorf("deletes read/unread = %d/%d, want 1/0", readDeletes.Load(), unreadDeletes.Load())
				}
			})
		}
	}
}

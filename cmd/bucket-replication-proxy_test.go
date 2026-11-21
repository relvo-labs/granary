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
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/minio/madmin-go/v3"
	miniogo "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/tags"
	"github.com/relvo-labs/granary/internal/auth"
	"github.com/relvo-labs/granary/internal/bucket/replication"
	xhttp "github.com/relvo-labs/granary/internal/http"
)

// Targets retain the supplied order for helper tests. API tests also exercise
// getProxyTargets, whose configuration map can return either target order.
func installTaggingProxyTargets(t *testing.T, bucket string, modes []string, handler http.HandlerFunc) *madmin.BucketTargets {
	t.Helper()
	sys := &BucketTargetSys{
		arnRemotesMap: make(map[string]arnTarget),
		targetsMap:    make(map[string][]madmin.BucketTarget),
		arnErrsMap:    make(map[string]arnErrs),
		hc:            make(map[string]epHealth),
	}
	targets := &madmin.BucketTargets{}
	for i, mode := range modes {
		arn := fmt.Sprintf("arn:minio:replication::test%d:remote-bucket", i)
		target := madmin.BucketTarget{Arn: arn, TargetBucket: "remote-bucket", Credentials: &madmin.Credentials{}}
		targets.Targets = append(targets.Targets, target)
		if mode == "clientless" {
			// Avoid the lazy metadata refresh when testing a missing client.
			sys.arnRemotesMap[arn] = arnTarget{lastRefresh: UTCNow()}
			continue
		}
		remote := httptest.NewServer(handler)
		t.Cleanup(remote.Close)
		client, err := miniogo.New(strings.TrimPrefix(remote.URL, "http://"), &miniogo.Options{Region: "us-east-1"})
		if err != nil {
			t.Fatal(err)
		}
		sys.arnRemotesMap[arn] = arnTarget{Client: &TargetClient{
			Client: client, Bucket: "remote-bucket", disableProxy: mode == "disabled",
		}}
		sys.hc[client.EndpointURL().Host] = epHealth{Online: mode != "offline"}
	}
	sys.targetsMap[bucket] = targets.Targets
	previous := globalBucketTargetSys
	globalBucketTargetSys = sys
	t.Cleanup(func() { globalBucketTargetSys = previous })
	return targets
}

func writeProxyTaggingError(w http.ResponseWriter, code string, status int) {
	w.Header().Set(xhttp.ContentType, "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<Error><Code>%s</Code><Message>test response</Message></Error>", code)
}

func TestProxyGetTaggingResponders(t *testing.T) {
	for _, skipped := range []string{"offline", "clientless", "disabled"} {
		for _, order := range []string{"first", "last", "only"} {
			t.Run(skipped+"/"+order, func(t *testing.T) {
				modes := []string{skipped, "active"}
				switch order {
				case "last":
					modes = []string{"active", skipped}
				case "only":
					modes = []string{skipped}
				}
				var calls atomic.Int32
				targets := installTaggingProxyTargets(t, "proxy-bucket", modes, func(w http.ResponseWriter, _ *http.Request) {
					calls.Add(1)
					fmt.Fprint(w, "<Tagging><TagSet><Tag><Key>test</Key><Value>denied</Value></Tag></TagSet></Tagging>")
				})
				got, result := proxyGetTaggingToRepTarget(t.Context(), "proxy-bucket", "object", ObjectOptions{}, targets)
				if order == "only" {
					if got != nil || result.Proxy || result.Err == nil || calls.Load() != 0 {
						t.Error("skipped targets must produce a distinct no-result outcome without a request")
					}
				} else if result.Err != nil || got == nil || got.String() != "test=denied" || calls.Load() != 1 {
					t.Error("skipped target replaced the responding target's tags")
				}
			})
		}
	}
}

func TestProxyGetTaggingConcurrentResponders(t *testing.T) {
	// Both requests arrive before either returns, exercising concurrent writes
	// to the helper's result slots under the race detector.
	var arrived sync.WaitGroup
	arrived.Add(2)
	targets := installTaggingProxyTargets(t, "proxy-bucket", []string{"active", "active"}, func(w http.ResponseWriter, _ *http.Request) {
		arrived.Done()
		arrived.Wait()
		fmt.Fprint(w, "<Tagging><TagSet><Tag><Key>test</Key><Value>value</Value></Tag></TagSet></Tagging>")
	})
	got, result := proxyGetTaggingToRepTarget(t.Context(), "proxy-bucket", "object", ObjectOptions{}, targets)
	if result.Err != nil || got == nil || got.String() != "test=value" {
		t.Error("concurrent responders did not return tags")
	}
}

func TestProxyTaggingResponders(t *testing.T) {
	for _, method := range []string{"put", "delete"} {
		for _, response := range []string{"success", "error", "skipped"} {
			t.Run(method+"/"+response, func(t *testing.T) {
				var calls atomic.Int32
				modes := []string{"active", "disabled"}
				if response == "skipped" {
					modes = []string{"offline", "disabled", "clientless"}
				}
				targets := installTaggingProxyTargets(t, "proxy-bucket", modes, func(w http.ResponseWriter, _ *http.Request) {
					calls.Add(1)
					if response == "error" {
						writeProxyTaggingError(w, "AccessDenied", http.StatusForbidden)
						return
					}
					if method == "put" {
						w.WriteHeader(http.StatusOK)
					} else {
						w.WriteHeader(http.StatusNoContent)
					}
				})
				var tagging *tags.Tags
				if method == "put" {
					tagging, _ = tags.ParseObjectTags("test=value")
				}
				result := proxyTaggingToRepTarget(t.Context(), "proxy-bucket", "object", tagging, ObjectOptions{}, targets)
				if (result.Err == nil) != (response == "success") {
					t.Error("skipped target counted as a successful tag mutation")
				}
				wantCalls := int32(1)
				if response == "skipped" {
					wantCalls = 0
				}
				if calls.Load() != wantCalls {
					t.Errorf("remote calls = %d, want %d", calls.Load(), wantCalls)
				}
			})
		}
	}
}

func TestAPITaggingProxyResponders(t *testing.T) {
	t.Cleanup(resetTestGlobals)
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testAPITaggingProxyResponders})
}

func testAPITaggingProxyResponders(_ ObjectLayer, instanceType, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
	user := newTaggingTestUser(t)
	for _, tc := range []struct {
		name, condition, tag, remoteError string
		modes                             []string
		wantStatus                        int
		wantCode                          string
		wantDeletes                       int32
	}{
		{name: "deny-existing-tag", condition: `"StringEquals":{"s3:ExistingObjectTag/test":"denied"}`, tag: "denied", modes: []string{"active", "disabled"}, wantStatus: http.StatusForbidden, wantCode: "AccessDenied"},
		{name: "deny-not-equal", condition: `"StringNotEquals":{"s3:ExistingObjectTag/test":"denied"}`, tag: "value", modes: []string{"active", "clientless"}, wantStatus: http.StatusForbidden, wantCode: "AccessDenied"},
		{name: "deny-tag-present", condition: `"Null":{"s3:ExistingObjectTag/test":"false"}`, tag: "denied", modes: []string{"active", "offline"}, wantStatus: http.StatusForbidden, wantCode: "AccessDenied"},
		{name: "read-failed", remoteError: "AccessDenied", modes: []string{"active", "disabled"}, wantStatus: http.StatusForbidden, wantCode: "AccessDenied"},
		{name: "no-responder", modes: []string{"offline", "clientless", "disabled"}, wantStatus: http.StatusNotFound, wantCode: "NoSuchKey"},
		{name: "missing-single", remoteError: "NoSuchKey", modes: []string{"active"}, wantStatus: http.StatusNotFound, wantCode: "NoSuchKey"},
		{name: "missing-multiple", remoteError: "NoSuchKey", modes: []string{"active", "active"}, wantStatus: http.StatusNotFound, wantCode: "NoSuchKey"},
		{name: "untagged", condition: `"StringEquals":{"s3:ExistingObjectTag/test":"denied"}`, modes: []string{"active", "disabled"}, wantStatus: http.StatusNoContent, wantDeletes: 1},
	} {
		t.Run(instanceType+"/"+tc.name, func(t *testing.T) {
			var reads, deletes atomic.Int32
			targets := installTaggingProxyTargets(t, bucket, tc.modes, func(w http.ResponseWriter, r *http.Request) {
				if !r.URL.Query().Has("tagging") {
					t.Error("unexpected non-tagging request")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				switch r.Method {
				case http.MethodGet:
					reads.Add(1)
					if tc.remoteError != "" {
						status := http.StatusForbidden
						if tc.remoteError == "NoSuchKey" {
							status = http.StatusNotFound
						}
						writeProxyTaggingError(w, tc.remoteError, status)
						return
					}
					tag := ""
					if tc.tag != "" {
						tag = "<Tag><Key>test</Key><Value>" + tc.tag + "</Value></Tag>"
					}
					fmt.Fprint(w, "<Tagging><TagSet>"+tag+"</TagSet></Tagging>")
				case http.MethodDelete:
					deletes.Add(1)
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Error("unexpected remote method")
					w.WriteHeader(http.StatusMethodNotAllowed)
				}
			})
			var rules strings.Builder
			for i, target := range targets.Targets {
				fmt.Fprintf(&rules, "<Rule><Priority>%d</Priority><Status>Enabled</Status><Filter><Prefix></Prefix></Filter><Destination><Bucket>%s</Bucket></Destination></Rule>", i+1, target.Arn)
			}
			meta := newBucketMetadata(bucket)
			var err error
			meta.replicationConfig, err = replication.ParseConfig(strings.NewReader("<ReplicationConfiguration>" + rules.String() + "</ReplicationConfiguration>"))
			if err != nil {
				t.Fatal(err)
			}
			globalBucketMetadataSys.Set(bucket, meta)
			statements := fmt.Sprintf(`{"Effect":"Allow","Action":["s3:DeleteObjectTagging","s3:GetObjectTagging"],"Resource":"arn:aws:s3:::%s/*"}`, bucket)
			if tc.condition != "" {
				statements += fmt.Sprintf(`,{"Effect":"Deny","Action":["s3:DeleteObjectTagging","s3:GetObjectTagging"],"Resource":"arn:aws:s3:::%s/*","Condition":{%s}}`, bucket, tc.condition)
			}
			setTaggingTestPolicy(t, bucket, user, statements)
			// Exercise configuration-map target ordering repeatedly. The helper
			// test above separately fixes the skipped target after the responder.
			for range 16 {
				before := deletes.Load()
				rec := taggingTestRequest(t, router, http.MethodDelete, getGetObjectURL("", bucket, "remote-only")+"?tagging", "", user)
				if rec.Code != tc.wantStatus {
					t.Errorf("DELETE HTTP %d, want %d", rec.Code, tc.wantStatus)
				}
				if got := deletes.Load() - before; got != tc.wantDeletes {
					t.Errorf("remote deletes = %d, want %d", got, tc.wantDeletes)
				}
				if tc.wantCode != "" {
					var response APIErrorResponse
					if err := xml.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.Code != tc.wantCode {
						t.Errorf("DELETE S3 error = %s, want %s", response.Code, tc.wantCode)
					}
				} else if rec.Header().Get(xhttp.MinIOTaggingProxied) != "true" {
					t.Error("successful delete missing proxied header")
				}
			}
			// GET uses the same tag read outcome and must retain successful
			// untagged responses and ordinary not-found errors.
			rec := taggingTestRequest(t, router, http.MethodGet, getGetObjectURL("", bucket, "remote-only")+"?tagging", "", user)
			want := tc.wantStatus
			if want == http.StatusNoContent {
				want = http.StatusOK
			}
			if rec.Code != want {
				t.Errorf("GET HTTP %d, want %d", rec.Code, want)
			}
			if want == http.StatusOK {
				var response objectTagging
				if err := xml.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.TagSet == nil || len(response.TagSet.Tags) != 0 {
					t.Error("untagged remote object did not return an empty tag set")
				}
				if rec.Header().Get(xhttp.MinIOTaggingProxied) != "true" {
					t.Error("successful GET missing proxied header")
				}
			}
			if tc.name == "no-responder" && reads.Load() != 0 {
				t.Error("skipped target received a read")
			}
		})
	}
}

// Keep production configuration setup separate from the explicitly ordered
// target lists used to verify agreement without relying on map iteration.
func setTaggingProxyConfig(t *testing.T, bucket string, targets *madmin.BucketTargets) {
	t.Helper()
	var rules strings.Builder
	for i, target := range targets.Targets {
		fmt.Fprintf(&rules, "<Rule><Priority>%d</Priority><Status>Enabled</Status><Filter><Prefix></Prefix></Filter><Destination><Bucket>%s</Bucket></Destination></Rule>", i+1, target.Arn)
	}
	meta := newBucketMetadata(bucket)
	var err error
	meta.replicationConfig, err = replication.ParseConfig(strings.NewReader("<ReplicationConfiguration>" + rules.String() + "</ReplicationConfiguration>"))
	if err != nil {
		t.Fatal(err)
	}
	globalBucketMetadataSys.Set(bucket, meta)
}

func checkProxyTaggingAPIError(t *testing.T, rec *httptest.ResponseRecorder, code APIErrorCode) {
	t.Helper()
	expected := getAPIError(code)
	var response APIErrorResponse
	if err := xml.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Errorf("decoding S3 error for HTTP %d: %v", rec.Code, err)
		return
	}
	if rec.Code != expected.HTTPStatusCode || response.Code != expected.Code || response.Message != expected.Description {
		t.Errorf("response = HTTP %d, %s, %q; want HTTP %d, %s, %q", rec.Code, response.Code, response.Message, expected.HTTPStatusCode, expected.Code, expected.Description)
	}
}

func TestAPITaggingProxyAgreement(t *testing.T) {
	t.Cleanup(resetTestGlobals)
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testAPITaggingProxyAgreement})
}

func testAPITaggingProxyAgreement(_ ObjectLayer, instanceType, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
	user := newTaggingTestUser(t)
	const allowed = "<Tag><Key>test</Key><Value>allowed</Value></Tag>"
	const denied = "<Tag><Key>test</Key><Value>denied</Value></Tag>"
	const extra = "<Tag><Key>extra</Key><Value>value</Value></Tag>"
	for _, policyType := range []string{"deny", "allow"} {
		for _, tc := range []struct {
			name     string
			tags     [2]string
			conflict bool
		}{
			{name: "conflict", tags: [2]string{denied, allowed}, conflict: true},
			{name: "tagged-and-empty", tags: [2]string{allowed, ""}, conflict: true},
			{name: "identical", tags: [2]string{allowed + extra, extra + allowed}},
			{name: "untagged", tags: [2]string{"", ""}},
		} {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/%s/reverse=%t", instanceType, policyType, tc.name, reverse), func(t *testing.T) {
					var deletes atomic.Int32
					byHost := make(map[string]string)
					targets := installTaggingProxyTargets(t, bucket, []string{"active", "active"}, func(w http.ResponseWriter, r *http.Request) {
						switch r.Method {
						case http.MethodGet:
							fmt.Fprint(w, "<Tagging><TagSet>"+byHost[r.Host]+"</TagSet></Tagging>")
						case http.MethodDelete:
							deletes.Add(1)
							w.WriteHeader(http.StatusNoContent)
						default:
							t.Error("unexpected remote method")
							w.WriteHeader(http.StatusMethodNotAllowed)
						}
					})
					for i, target := range targets.Targets {
						client := globalBucketTargetSys.GetRemoteTargetClient(bucket, target.Arn)
						byHost[client.EndpointURL().Host] = tc.tags[i]
					}
					ordered := &madmin.BucketTargets{Targets: append([]madmin.BucketTarget(nil), targets.Targets...)}
					if reverse {
						ordered.Targets[0], ordered.Targets[1] = ordered.Targets[1], ordered.Targets[0]
					}
					setTaggingProxyConfig(t, bucket, ordered)
					statements := fmt.Sprintf(`{"Effect":"Allow","Action":["s3:DeleteObjectTagging","s3:GetObjectTagging"],"Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"allowed"}}}`, bucket)
					if policyType == "deny" {
						statements = fmt.Sprintf(`{"Effect":"Allow","Action":["s3:DeleteObjectTagging","s3:GetObjectTagging"],"Resource":"arn:aws:s3:::%s/*"},{"Effect":"Deny","Action":["s3:DeleteObjectTagging","s3:GetObjectTagging"],"Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"denied"}}}`, bucket, bucket)
					}
					setTaggingTestPolicy(t, bucket, user, statements)
					// These two explicit target orders make the agreement
					// regression deterministic even though the API loads a map.
					got, result := proxyGetTaggingToRepTarget(t.Context(), bucket, "agreement", ObjectOptions{}, ordered)
					if tc.conflict {
						if got != nil || result.Proxy || toAPIError(t.Context(), result.Err).Code != "AccessDenied" {
							t.Error("conflicting tag sets did not fail closed in the explicit target order")
						}
					} else if result.Err != nil || !result.Proxy || got == nil {
						t.Error("identical tag sets did not produce a successful result")
					}
					// Exercise both HTTP callers repeatedly as they obtain
					// target order from the replication configuration map.
					attempts := 1
					if tc.conflict {
						attempts = 16
					}
					for range attempts {
						for _, method := range []string{http.MethodGet, http.MethodDelete} {
							before := deletes.Load()
							rec := taggingTestRequest(t, router, method, getGetObjectURL("", bucket, "agreement")+"?tagging", "", user)
							reject := tc.conflict || (tc.name == "untagged" && policyType == "allow")
							expectedDeletes := int32(0)
							if reject {
								checkProxyTaggingAPIError(t, rec, ErrAccessDenied)
							} else {
								want := http.StatusOK
								if method == http.MethodDelete {
									want = http.StatusNoContent
									expectedDeletes = 2
								}
								if rec.Code != want || rec.Header().Get(xhttp.MinIOTaggingProxied) != "true" {
									t.Errorf("identical responders: HTTP %d, want proxied HTTP %d", rec.Code, want)
								}
							}
							if tc.conflict && rec.Header().Get(xhttp.MinIOTaggingProxied) != "" {
								t.Error("conflicting responders claimed proxy success")
							}
							if got := deletes.Load() - before; got != expectedDeletes {
								t.Errorf("remote deletes = %d, want %d", got, expectedDeletes)
							}
						}
					}
				})
			}
		}
	}
}

func TestAPITaggingProxyMutationNoResult(t *testing.T) {
	t.Cleanup(resetTestGlobals)
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testAPITaggingProxyMutationNoResult})
}

func testAPITaggingProxyMutationNoResult(obj ObjectLayer, instanceType, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
	// A local object with a missing requested version covers NoSuchVersion as
	// well as a wholly absent object's NoSuchKey.
	if _, err := obj.PutObject(t.Context(), bucket, "local-object", mustGetPutObjReader(t, strings.NewReader("data"), 4, "", ""), ObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	user := newTaggingTestUser(t)
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		for _, version := range []string{"", "a3348c34-c352-4498-82f0-1098e8b34df9"} {
			t.Run(instanceType+"/"+method+"/"+version, func(t *testing.T) {
				var reads, mutations atomic.Int32
				modes := []string{"offline", "clientless", "disabled"}
				if method == http.MethodDelete {
					modes = []string{"active"}
				}
				targets := installTaggingProxyTargets(t, bucket, modes, func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet {
						reads.Add(1)
						// Become unavailable before returning a successful tag
						// read, so the subsequent mutation skips this target.
						globalBucketTargetSys.markOffline(&url.URL{Host: r.Host})
						fmt.Fprint(w, "<Tagging><TagSet><Tag><Key>test</Key><Value>allowed</Value></Tag></TagSet></Tagging>")
						return
					}
					mutations.Add(1)
					if r.Method == http.MethodPut {
						w.WriteHeader(http.StatusOK)
					} else {
						w.WriteHeader(http.StatusNoContent)
					}
				})
				setTaggingProxyConfig(t, bucket, targets)
				setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(`{"Effect":"Allow","Action":["s3:PutObjectTagging","s3:DeleteObjectTagging"],"Resource":"arn:aws:s3:::%s/*"}`, bucket))
				object := "remote-only"
				code := ErrNoSuchKey
				if version != "" {
					object = "local-object"
					code = ErrNoSuchVersion
				}
				target := getGetObjectURL("", bucket, object) + "?tagging"
				if version != "" {
					target += "&versionId=" + version
				}
				body := ""
				if method == http.MethodPut {
					body = "<Tagging><TagSet><Tag><Key>test</Key><Value>allowed</Value></Tag></TagSet></Tagging>"
				}
				rec := taggingTestRequest(t, router, method, target, body, user)
				checkProxyTaggingAPIError(t, rec, code)
				if rec.Header().Get(xhttp.MinIOTaggingProxied) != "" {
					t.Error("unavailable mutation claimed proxy success")
				}
				wantReads := int32(0)
				if method == http.MethodDelete {
					wantReads = 1
				}
				if reads.Load() != wantReads || mutations.Load() != 0 {
					t.Errorf("remote reads/mutations = %d/%d, want %d/0", reads.Load(), mutations.Load(), wantReads)
				}
			})
		}
	}
}

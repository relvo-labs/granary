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

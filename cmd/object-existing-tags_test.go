// Copyright (c) 2026 Granary contributors.
//
// This file is part of Granary, an unofficial fork derived from MinIO.
// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	miniogo "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/tags"
	"github.com/relvo-labs/granary/internal/auth"
	objectlock "github.com/relvo-labs/granary/internal/bucket/object/lock"
	"github.com/relvo-labs/granary/internal/bucket/replication"
	"github.com/relvo-labs/granary/internal/config"
	"github.com/relvo-labs/granary/internal/config/lambda"
	levent "github.com/relvo-labs/granary/internal/config/lambda/event"
	xhttp "github.com/relvo-labs/granary/internal/http"
)

func existingTagsTestRequest(t *testing.T, router http.Handler, method, target, body string, header http.Header, cred auth.Credentials) *httptest.ResponseRecorder {
	t.Helper()
	req, err := newTestRequest(method, target, int64(len(body)), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, values := range header {
		req.Header[k] = append([]string(nil), values...)
	}
	if cred.AccessKey != "" {
		if err = signRequestV4(req, cred.AccessKey, cred.SecretKey); err != nil {
			t.Fatal(err)
		}
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestAPIExistingObjectTags(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testAPIExistingObjectTags})
}

func testAPIExistingObjectTags(obj ObjectLayer, instanceType, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
	globalBucketMetadataSys.Set(bucket, newBucketMetadata(bucket))
	user := newTaggingTestUser(t)
	setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(`{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectVersion","s3:GetObjectAttributes","s3:GetObjectVersionAttributes","s3:GetObjectTagging","s3:DeleteObjectTagging"],"Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"value"}}}`, bucket))
	for _, versioned := range []bool{false, true} {
		for _, stored := range []string{"", "test=value", "test=denied"} {
			for _, client := range []string{"", "test=value", "test=denied"} {
				for _, operation := range []string{"GET", "HEAD", "GET-tagging", "DELETE-tagging", "attributes"} {
					for _, identity := range []struct {
						name string
						cred auth.Credentials
					}{{"signed-user", user}, {"anonymous", auth.AnonymousCredentials}} {
						t.Run(fmt.Sprintf("%s/%s/versioned=%t/stored=%s/client=%s/%s", instanceType, identity.name, versioned, stored, client, operation), func(t *testing.T) {
							const object = "existing-tags"
							opts := ObjectOptions{Versioned: versioned, UserDefined: map[string]string{xhttp.AmzObjectTagging: stored}}
							info, err := obj.PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, strings.NewReader("data"), 4, "", ""), opts)
							if err != nil {
								t.Fatal(err)
							}
							query := url.Values{}
							if versioned {
								if info.VersionID == "" {
									t.Fatal("missing fixture version ID")
								}
								query.Set(xhttp.VersionID, info.VersionID)
								// The selected version's tags must win over the latest version's tags.
								opts.UserDefined[xhttp.AmzObjectTagging] = "test=latest"
								if _, err = obj.PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, strings.NewReader("new"), 3, "", ""), opts); err != nil {
									t.Fatal(err)
								}
							}
							method, want := operation, http.StatusOK
							header := http.Header{}
							if client != "" {
								header.Set(xhttp.AmzObjectTagging, client)
							}
							switch operation {
							case "GET-tagging":
								method = http.MethodGet
								query.Set("tagging", "")
							case "DELETE-tagging":
								method = http.MethodDelete
								query.Set("tagging", "")
								want = http.StatusNoContent
							case "attributes":
								method = http.MethodGet
								query.Set("attributes", "")
								header.Set(xhttp.AmzObjectAttributes, "ETag,ObjectSize")
							}
							if stored != "test=value" {
								want = http.StatusForbidden
							}
							target := getGetObjectURL("", bucket, object) + "?" + query.Encode()
							rec := existingTagsTestRequest(t, router, method, target, "", header, identity.cred)
							if rec.Code != want {
								t.Errorf("HTTP %d, want %d", rec.Code, want)
							}
							if want == http.StatusForbidden && method != http.MethodHead {
								var response APIErrorResponse
								if err := xml.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.Code != "AccessDenied" {
									t.Error("expected S3 AccessDenied")
								}
							}
							if operation == "DELETE-tagging" {
								got, err := obj.GetObjectTags(t.Context(), bucket, object, ObjectOptions{VersionID: info.VersionID})
								if err != nil {
									t.Fatal(err)
								}
								expected := stored
								if want == http.StatusNoContent {
									expected = ""
								}
								if got.String() != expected {
									t.Error("unexpected stored tags after delete")
								}
							}
						})
					}
				}
			}
		}
	}
}

// These sibling reads also authorize GetObject, including the source side of
// copy operations. Destination request tags must remain available independently.
func TestAPIExistingObjectTagsSiblingReads(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testAPIExistingObjectTagsSiblingReads})
}

func testAPIExistingObjectTagsSiblingReads(obj ObjectLayer, instanceType, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
	globalBucketMetadataSys.Set(bucket, newBucketMetadata(bucket))
	user := newTaggingTestUser(t)

	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	entry, err := zw.Create("file.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(entry, "data"); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	const route, token = "existing-tags-route", "existing-tags-token"
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			calls.Add(1)
		}
		w.Header().Set(xhttp.AmzRequestRoute, route)
		w.Header().Set(xhttp.AmzRequestToken, token)
		_, _ = io.WriteString(w, "data")
	}))
	defer remote.Close()
	cfg := config.New()
	cfg[config.LambdaWebhookSubSys] = map[string]config.KVS{"existing-tags": {
		{Key: "endpoint", Value: remote.URL}, {Key: "enable", Value: config.EnableOn},
	}}
	previousTargets, previousEvent := globalLambdaTargetList, getLambdaEventData
	globalLambdaTargetList, err = lambda.FetchEnabledTargets(t.Context(), cfg, http.DefaultTransport.(*http.Transport))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		globalLambdaTargetList = previousTargets
		getLambdaEventData = previousEvent
	}()
	getLambdaEventData = func(_, _ string, _ auth.Credentials, _ *http.Request) (levent.Event, error) {
		return levent.Event{GetObjectContext: &levent.GetObjectContext{OutputRoute: route, OutputToken: token}}, nil
	}

	for _, stored := range []string{"", "test=value", "test=denied"} {
		for _, client := range []string{"test=value", "test=destination"} {
			for _, operation := range []string{"select", "archive-GET", "archive-HEAD", "copy", "copy-part", "lambda"} {
				for _, identity := range []struct {
					name string
					cred auth.Credentials
				}{{"signed-user", user}, {"anonymous", auth.AnonymousCredentials}} {
					t.Run(fmt.Sprintf("%s/%s/stored=%s/client=%s/%s", instanceType, identity.name, stored, client, operation), func(t *testing.T) {
						condition := `,"Condition":{"StringEquals":{"s3:RequestObjectTag/test":["destination","value"]}}`
						if operation == "copy-part" {
							// UploadPartCopy has no tagging input; tags belong to initiation.
							condition = ""
						}
						setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(
							`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"value"}}},
							{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::%s/destination"%s}`, bucket, bucket, condition))
						object, data := "source", "data"
						header := http.Header{}
						header.Set(xhttp.AmzObjectTagging, client)
						method, body, query := http.MethodGet, "", url.Values{}
						switch operation {
						case "select":
							method = http.MethodPost
							body = `<SelectObjectContentRequest><Expression>SELECT * FROM S3Object</Expression><ExpressionType>SQL</ExpressionType><InputSerialization><CSV/></InputSerialization><OutputSerialization><CSV/></OutputSerialization></SelectObjectContentRequest>`
							query.Set("select", "")
							query.Set("select-type", "2")
						case "archive-GET", "archive-HEAD":
							object, data = "source.zip", archive.String()
							header.Set(xMinIOExtract, "true")
							if operation == "archive-HEAD" {
								method = http.MethodHead
							}
						case "lambda":
							query.Set("lambdaArn", "arn:minio:s3-object-lambda::existing-tags:webhook")
						}
						if _, err := obj.PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, strings.NewReader(data), int64(len(data)), "", ""), ObjectOptions{UserDefined: map[string]string{xhttp.AmzObjectTagging: stored}}); err != nil {
							t.Fatal(err)
						}
						target := getGetObjectURL("", bucket, object)
						if strings.HasPrefix(operation, "archive-") {
							target += "/file.txt"
						}
						if operation == "copy" || operation == "copy-part" {
							method = http.MethodPut
							target = getGetObjectURL("", bucket, "destination")
							header.Set(xhttp.AmzCopySource, "/"+bucket+"/"+object)
							header.Set(xhttp.AmzTagDirective, "REPLACE")
							header.Set(xhttp.AmzObjectTagging, client)
							if operation == "copy-part" {
								upload, err := obj.NewMultipartUpload(t.Context(), bucket, "destination", ObjectOptions{})
								if err != nil {
									t.Fatal(err)
								}
								defer obj.AbortMultipartUpload(t.Context(), bucket, "destination", upload.UploadID, ObjectOptions{})
								query.Set("uploadId", upload.UploadID)
								query.Set("partNumber", "1")
							}
						}
						before := calls.Load()
						rec := existingTagsTestRequest(t, router, method, target+"?"+query.Encode(), body, header, identity.cred)
						want := http.StatusForbidden
						if stored == "test=value" {
							want = http.StatusOK
						}
						if rec.Code != want {
							t.Errorf("HTTP %d, want %d", rec.Code, want)
						}
						if operation == "lambda" {
							expected := int32(0)
							if want == http.StatusOK {
								expected = 1
							}
							if calls.Load()-before != expected {
								t.Error("unexpected lambda invocation count")
							}
						}
						if operation == "copy" && want == http.StatusOK && rec.Code == want {
							got, err := obj.GetObjectTags(t.Context(), bucket, "destination", ObjectOptions{})
							if err != nil || got.String() != client {
								t.Error("copy did not preserve destination request tags")
							}
						}
					})
				}
			}
		}
	}
}

func TestAPIRequestObjectTagsUnaffected(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instanceType, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
		globalBucketMetadataSys.Set(bucket, newBucketMetadata(bucket))
		user := newTaggingTestUser(t)
		setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(`{"Effect":"Allow","Action":["s3:PutObject","s3:PutObjectTagging"],"Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{"s3:RequestObjectTag/test":"value"}}}`, bucket))
		for _, operation := range []string{"put", "put-tagging"} {
			for _, value := range []string{"value", "denied"} {
				t.Run(instanceType+"/"+operation+"/"+value, func(t *testing.T) {
					const object = "request-tags"
					if _, err := obj.PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, strings.NewReader("old"), 3, "", ""), ObjectOptions{UserDefined: map[string]string{xhttp.AmzObjectTagging: "test=old"}}); err != nil {
						t.Fatal(err)
					}
					header := http.Header{}
					header.Set(xhttp.AmzObjectTagging, "test="+value)
					target, body := getGetObjectURL("", bucket, object), "new"
					if operation == "put-tagging" {
						target += "?tagging"
						body = "<Tagging><TagSet><Tag><Key>test</Key><Value>" + value + "</Value></Tag></TagSet></Tagging>"
						// The XML supplies request tags; this conflicting signed header must lose.
						header.Set(xhttp.AmzObjectTagging, "test=header")
					}
					rec := existingTagsTestRequest(t, router, http.MethodPut, target, body, header, user)
					want, expected := http.StatusOK, "test=value"
					if value != "value" {
						want, expected = http.StatusForbidden, "test=old"
					}
					if rec.Code != want {
						t.Errorf("HTTP %d, want %d", rec.Code, want)
					}
					got, err := obj.GetObjectTags(t.Context(), bucket, object, ObjectOptions{})
					if err != nil || got.String() != expected {
						t.Error("unexpected tags after request-tag authorization")
					}
				})
			}
		}
	}})
}

func TestAPIExistingObjectTagsProxy(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testAPIExistingObjectTagsProxy})
}

func testAPIExistingObjectTagsProxy(_ ObjectLayer, instanceType, bucket string, router http.Handler, root auth.Credentials, t *testing.T) {
	var stored string
	var removes atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/remote-bucket/absent" {
			t.Error("unexpected remote object")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Query().Has("tagging") {
			if r.Method == http.MethodDelete {
				removes.Add(1)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			objectTags, err := tags.ParseObjectTags(stored)
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set(xhttp.ContentType, "application/xml")
			if err := xml.NewEncoder(w).Encode(objectTags); err != nil {
				t.Error(err)
			}
			return
		}
		w.Header().Set(xhttp.LastModified, time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set(xhttp.ETag, "\"d41d8cd98f00b204e9800998ecf8427e\"")
		w.Header().Set(xhttp.ContentLength, "4")
		w.Header().Set(xhttp.AmzObjectTagging, stored)
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, "data")
		}
	}))
	defer remote.Close()
	client, err := miniogo.New(strings.TrimPrefix(remote.URL, "http://"), &miniogo.Options{
		Creds: credentials.NewStaticV4(root.AccessKey, root.SecretKey, ""), Region: "us-east-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	const arn = "arn:minio:replication::test:remote-bucket"
	meta := newBucketMetadata(bucket)
	meta.replicationConfig, err = replication.ParseConfig(strings.NewReader(`<ReplicationConfiguration><Rule><Status>Enabled</Status><Filter><Prefix></Prefix></Filter><Destination><Bucket>` + arn + `</Bucket></Destination></Rule></ReplicationConfiguration>`))
	if err != nil {
		t.Fatal(err)
	}
	globalBucketMetadataSys.Set(bucket, meta)
	previous := globalBucketTargetSys
	globalBucketTargetSys = &BucketTargetSys{
		arnRemotesMap: map[string]arnTarget{arn: {Client: &TargetClient{Client: client, Bucket: "remote-bucket"}}},
		targetsMap:    map[string][]madmin.BucketTarget{bucket: {{Arn: arn, TargetBucket: "remote-bucket", Credentials: &madmin.Credentials{}}}},
		hc:            map[string]epHealth{client.EndpointURL().Host: {Online: true}},
	}
	defer func() { globalBucketTargetSys = previous }()
	user := newTaggingTestUser(t)
	setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(`{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectTagging","s3:DeleteObjectTagging"],"Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"value"}}}`, bucket))
	for _, remoteTags := range []string{"", "test=value", "test=denied"} {
		stored = remoteTags
		for _, clientTags := range []string{"test=value", "test=denied"} {
			for _, operation := range []string{"GET", "HEAD", "GET-tagging", "DELETE-tagging"} {
				for _, identity := range []struct {
					name string
					cred auth.Credentials
				}{{"signed-user", user}, {"anonymous", auth.AnonymousCredentials}} {
					t.Run(instanceType+"/"+identity.name+"/stored="+stored+"/client="+clientTags+"/"+operation, func(t *testing.T) {
						header := http.Header{}
						header.Set(xhttp.AmzObjectTagging, clientTags)
						method, target, want := operation, getGetObjectURL("", bucket, "absent"), http.StatusOK
						if strings.HasSuffix(operation, "-tagging") {
							method = strings.TrimSuffix(operation, "-tagging")
							target += "?tagging"
							if method == http.MethodDelete {
								want = http.StatusNoContent
							}
						}
						if stored != "test=value" {
							want = http.StatusForbidden
						}
						before := removes.Load()
						rec := existingTagsTestRequest(t, router, method, target, "", header, identity.cred)
						if rec.Code != want {
							t.Errorf("HTTP %d, want %d", rec.Code, want)
						}
						expected := int32(0)
						if operation == "DELETE-tagging" && want == http.StatusNoContent {
							expected = 1
						}
						if removes.Load()-before != expected {
							t.Error("unexpected remote tag removal")
						}
					})
				}
			}
		}
	}
}

func TestAPIExistingObjectTagsReplicaDelete(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instanceType, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
		globalBucketMetadataSys.Set(bucket, newBucketMetadata(bucket))
		user := newTaggingTestUser(t)
		setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(
			`{"Effect":"Allow","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::%s/*"},
			{"Effect":"Allow","Action":"s3:ReplicateDelete","Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"value"}}}`, bucket, bucket))
		for _, stored := range []string{"", "test=value", "test=denied"} {
			for _, client := range []string{"test=value", "test=denied"} {
				t.Run(instanceType+"/stored="+stored+"/client="+client, func(t *testing.T) {
					const object = "replica-delete"
					if _, err := obj.PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, strings.NewReader("data"), 4, "", ""), ObjectOptions{UserDefined: map[string]string{xhttp.AmzObjectTagging: stored}}); err != nil {
						t.Fatal(err)
					}
					header := http.Header{}
					header.Set(xhttp.AmzObjectTagging, client)
					header.Set(xhttp.AmzBucketReplicationStatus, "REPLICA")
					rec := existingTagsTestRequest(t, router, http.MethodDelete, getGetObjectURL("", bucket, object), "", header, user)
					want := http.StatusForbidden
					if stored == "test=value" {
						want = http.StatusNoContent
					}
					if rec.Code != want {
						t.Errorf("HTTP %d, want %d", rec.Code, want)
					}
					if want == http.StatusForbidden {
						if _, err := obj.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{}); err != nil {
							t.Error("denied replication delete removed the object")
						}
					}
				})
			}
		}
		// The extra metadata lookup must preserve replication's handling of
		// absent objects and explicit delete-marker versions with unconditional grants.
		setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(
			`{"Effect":"Allow","Action":["s3:DeleteObject","s3:ReplicateDelete"],"Resource":"arn:aws:s3:::%s/*"}`, bucket))
		for _, marker := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/delete-marker=%t", instanceType, marker), func(t *testing.T) {
				const object = "replica-missing"
				target := getGetObjectURL("", bucket, object)
				if marker {
					if _, err := obj.PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, strings.NewReader("data"), 4, "", ""), ObjectOptions{Versioned: true}); err != nil {
						t.Fatal(err)
					}
					info, err := obj.DeleteObject(t.Context(), bucket, object, ObjectOptions{Versioned: true})
					if err != nil || info.VersionID == "" || !info.DeleteMarker {
						t.Fatal("failed to create delete-marker fixture")
					}
					target += "?versionId=" + info.VersionID
				}
				header := http.Header{}
				header.Set(xhttp.AmzBucketReplicationStatus, "REPLICA")
				rec := existingTagsTestRequest(t, router, http.MethodDelete, target, "", header, user)
				if rec.Code != http.StatusNoContent {
					t.Errorf("HTTP %d, want 204", rec.Code)
				}
			})
		}
	}})
}

func TestAPIExistingObjectTagsWildcardActions(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instanceType, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
		meta := newBucketMetadata(bucket)
		meta.objectLockConfig = &objectlock.Config{ObjectLockEnabled: objectlock.Enabled}
		globalBucketMetadataSys.Set(bucket, meta)
		user := newTaggingTestUser(t)
		// Wildcard condition keys are the union of matching actions' keys.
		setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(
			`{"Effect":"Allow","Action":["s3:GetObject*","s3:DeleteObject*"],"Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"value"}}}`, bucket))
		for _, stored := range []string{"", "test=value", "test=denied"} {
			for _, client := range []string{"test=value", "test=denied"} {
				for _, operation := range []string{"retention", "legal-hold", "delete", "bulk-delete"} {
					for _, identity := range []struct {
						name string
						cred auth.Credentials
					}{{"signed-user", user}, {"anonymous", auth.AnonymousCredentials}} {
						t.Run(instanceType+"/"+identity.name+"/stored="+stored+"/client="+client+"/"+operation, func(t *testing.T) {
							const object = "wildcard-tags"
							metadata := map[string]string{xhttp.AmzObjectTagging: stored}
							if operation == "retention" || operation == "legal-hold" {
								metadata[strings.ToLower(xhttp.AmzObjectLockMode)] = "GOVERNANCE"
								metadata[strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)] = UTCNow().Add(time.Hour).Format(time.RFC3339)
								metadata[strings.ToLower(xhttp.AmzObjectLockLegalHold)] = "ON"
							}
							if _, err := obj.PutObject(t.Context(), bucket, object, mustGetPutObjReader(t, strings.NewReader("data"), 4, "", ""), ObjectOptions{UserDefined: metadata}); err != nil {
								t.Fatal(err)
							}
							header := http.Header{}
							header.Set(xhttp.AmzObjectTagging, client)
							method, target, body, want := http.MethodGet, getGetObjectURL("", bucket, object)+"?"+operation, "", http.StatusOK
							if operation == "delete" {
								method, target, want = http.MethodDelete, getGetObjectURL("", bucket, object), http.StatusNoContent
							}
							if operation == "bulk-delete" {
								method, target = http.MethodPost, "/"+bucket+"?delete"
								body = "<Delete><Object><Key>" + object + "</Key></Object><Object><Key>other</Key></Object></Delete>"
								if _, err := obj.PutObject(t.Context(), bucket, "other", mustGetPutObjReader(t, strings.NewReader("data"), 4, "", ""), ObjectOptions{}); err != nil {
									t.Fatal(err)
								}
							} else if stored != "test=value" {
								want = http.StatusForbidden
							}
							rec := existingTagsTestRequest(t, router, method, target, body, header, identity.cred)
							if rec.Code != want {
								t.Errorf("HTTP %d, want %d", rec.Code, want)
							}
							if operation == "bulk-delete" && rec.Code == http.StatusOK {
								var result struct {
									Errors  []struct{ Key, Code string } `xml:"Error"`
									Deleted []struct{ Key string }       `xml:"Deleted"`
								}
								if err := xml.Unmarshal(rec.Body.Bytes(), &result); err != nil {
									t.Fatal(err)
								}
								denied := map[string]bool{}
								for _, e := range result.Errors {
									if e.Code != "AccessDenied" {
										t.Error("expected per-object AccessDenied")
									}
									denied[e.Key] = true
								}
								if denied[object] != (stored != "test=value") || !denied["other"] {
									t.Error("bulk delete did not use each object's stored tags")
								}
							}
						})
					}
				}
			}
		}
	}})
}

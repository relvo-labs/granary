// Copyright (c) 2026 Granary contributors.
//
// This file is part of Granary, an unofficial fork derived from MinIO.
// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	xnet "github.com/minio/pkg/v3/net"
	"github.com/relvo-labs/granary/internal/auth"
	objectlock "github.com/relvo-labs/granary/internal/bucket/object/lock"
	"github.com/relvo-labs/granary/internal/config"
	"github.com/relvo-labs/granary/internal/config/lambda"
	levent "github.com/relvo-labs/granary/internal/config/lambda/event"
	xhttp "github.com/relvo-labs/granary/internal/http"
)

func repairTagFixture(t *testing.T, obj ObjectLayer, bucket, object, stored string, versioned bool) ObjectInfo {
	t.Helper()
	info, err := obj.PutObject(t.Context(), bucket, object,
		mustGetPutObjReader(t, strings.NewReader("data"), 4, "", ""),
		ObjectOptions{Versioned: versioned, UserDefined: map[string]string{xhttp.AmzObjectTagging: stored}})
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestRepairReservedConditions(t *testing.T) {
	for _, source := range []string{"query", "header"} {
		t.Run(source, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost/bucket/object", nil)
			inputs := map[string]string{
				"ExistingObjectTag/test": "new", "eXiStInGoBjEcTtAg%2Ftest": "new",
				"RequestObjectTag/test": "new", "RequestObjectTagKeys": "test",
				"CurrentTime": "spoof", "EpochTime": "spoof", "SecureTransport": "true",
				"SourceIp": "spoof", "username": "spoof", "userid": "spoof",
				"principaltype": "spoof", "signatureversion": "spoof", "authType": "spoof",
				"signatureAge": "spoof", "x-amz-signature-age": "spoof", "versionid": "spoof", "groups": "spoof",
				"sub": "spoof", "email": "spoof", "custom-claim": "spoof",
				"LocationConstraint": "spoof", "object-lock-mode": "spoof",
				"object-lock-remaining-retention-days": "spoof",
			}
			req.Form = url.Values{}
			for key, value := range inputs {
				if source == "query" {
					req.Form.Set(key, value)
				} else {
					req.Header.Set(key, value)
				}
			}
			req.Header.Set(xhttp.AmzObjectTagging, "test=new")
			req.Form.Set("prefix", "allowed-prefix")
			req.URL.RawQuery = req.Form.Encode()
			values := getConditionValues(req, "", auth.Credentials{
				AccessKey: "fixture-user", Groups: []string{"actual-group"},
				Claims: map[string]any{"custom-claim": "actual-claim"},
			})
			for key, got := range values {
				for _, value := range got {
					if value == "spoof" {
						t.Errorf("raw %s injected condition %s", source, key)
					}
				}
				if strings.HasPrefix(strings.ToLower(key), "existingobjecttag") || strings.HasPrefix(strings.ToLower(key), "requestobjecttag") {
					t.Errorf("read request injected tag condition %s", key)
				}
			}
			if got := values["groups"]; len(got) != 1 || got[0] != "actual-group" {
				t.Error("credential groups were replaced")
			}
			if got := values["prefix"]; len(got) != 1 || got[0] != "allowed-prefix" {
				t.Error("ordinary request condition was lost")
			}
		})
	}
}

func TestAPIRepairTagQueryInjection(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
		globalBucketMetadataSys.Set(bucket, newBucketMetadata(bucket))
		user := newTaggingTestUser(t)
		setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(`{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectTagging","s3:DeleteObjectTagging"],"Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"new"}}}`, bucket))
		for _, stored := range []string{"", "test=new", "test=other"} {
			for _, operation := range []string{"GET", "HEAD", "GET-tagging", "DELETE-tagging"} {
				for _, identity := range []struct {
					name string
					cred auth.Credentials
				}{{"user", user}, {"anonymous", auth.AnonymousCredentials}} {
					for _, key := range []string{"ExistingObjectTag/test", "eXiStInGoBjEcTtAg%2Ftest"} {
						t.Run(instance+"/"+identity.name+"/"+stored+"/"+operation+"/"+key, func(t *testing.T) {
							repairTagFixture(t, obj, bucket, "query-tags", stored, false)
							query := url.Values{key: {"new"}, "RequestObjectTag/test": {"new"}}
							method, want := operation, http.StatusOK
							if strings.HasSuffix(operation, "-tagging") {
								method = strings.TrimSuffix(operation, "-tagging")
								query.Set("tagging", "")
								if method == http.MethodDelete {
									want = http.StatusNoContent
								}
							}
							if stored != "test=new" {
								want = http.StatusForbidden
							}
							rec := existingTagsTestRequest(t, router, method, getGetObjectURL("", bucket, "query-tags")+"?"+query.Encode(), "", nil, identity.cred)
							if rec.Code != want {
								t.Errorf("HTTP %d, want %d", rec.Code, want)
							}
						})
					}
				}
			}
		}
	}})
}

func TestAPIRepairWriteTagSeparation(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
		globalBucketMetadataSys.Set(bucket, newBucketMetadata(bucket))
		user := newTaggingTestUser(t)
		for _, operation := range []string{"tagging", "tagging-same", "put", "put-same", "copy-replace", "copy-replace-same", "initiate", "initiate-same", "replicate", "replicate-same"} {
			baseOperation := strings.TrimSuffix(operation, "-same")
			statements := fmt.Sprintf(`{"Effect":"Allow","Action":"s3:PutObject*","Resource":"arn:aws:s3:::%s/destination","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"old","s3:RequestObjectTag/test":"new"}}}`, bucket)
			existing := "old"
			if strings.HasSuffix(operation, "-same") {
				existing = "new"
				statements = strings.ReplaceAll(statements, `"s3:ExistingObjectTag/test":"old"`, `"s3:ExistingObjectTag/test":"new"`)
			}
			if baseOperation == "copy-replace" {
				statements += fmt.Sprintf(`,{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/source","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"source"}}}`, bucket)
			}
			if baseOperation == "replicate" {
				statements = fmt.Sprintf(`{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::%s/destination","Condition":{"StringEquals":{"s3:RequestObjectTag/test":"new"}}},
				{"Effect":"Allow","Action":"s3:ReplicateObject","Resource":"arn:aws:s3:::%s/destination","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"%s"}}}`, bucket, bucket, existing)
			}
			setTaggingTestPolicy(t, bucket, user, statements)
			for _, stored := range []string{"", "test=old", "test=new"} {
				for _, versioned := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/versioned=%t", instance, operation, stored, versioned), func(t *testing.T) {
						info := repairTagFixture(t, obj, bucket, "destination", stored, versioned)
						query := url.Values{}
						if versioned {
							query.Set(xhttp.VersionID, info.VersionID)
							repairTagFixture(t, obj, bucket, "destination", "test=latest", true)
						}
						header := http.Header{}
						header.Set(xhttp.AmzObjectTagging, "test=new")
						method, body := http.MethodPut, "data"
						switch baseOperation {
						case "tagging":
							query.Set("tagging", "")
							body = "<Tagging><TagSet><Tag><Key>test</Key><Value>new</Value></Tag></TagSet></Tagging>"
							header.Set(xhttp.AmzObjectTagging, "test=header")
						case "copy-replace":
							source := repairTagFixture(t, obj, bucket, "source", "test=source", true)
							repairTagFixture(t, obj, bucket, "source", "test=latest", true)
							header.Set(xhttp.AmzCopySource, "/"+bucket+"/source?versionId="+source.VersionID)
							header.Set(xhttp.AmzTagDirective, "REPLACE")
							body = ""
						case "initiate":
							method, body = http.MethodPost, ""
							query.Set("uploads", "")
						case "replicate":
							header.Set(xhttp.AmzBucketReplicationStatus, "REPLICA")
						}
						// PutObject and multipart creation do not accept an arbitrary destination
						// version on an unversioned bucket. Versioned selection is exercised by
						// tagging and by the source side of copy.
						if versioned && baseOperation != "tagging" {
							query.Del(xhttp.VersionID)
							repairTagFixture(t, obj, bucket, "destination", stored, false)
						}
						rec := existingTagsTestRequest(t, router, method, getGetObjectURL("", bucket, "destination")+"?"+query.Encode(), body, header, user)
						want := http.StatusForbidden
						if stored == "test="+existing {
							want = http.StatusOK
						}
						if rec.Code != want {
							t.Errorf("HTTP %d, want %d", rec.Code, want)
						}
						if baseOperation == "initiate" && rec.Code == http.StatusOK {
							var result struct {
								UploadID string `xml:"UploadId"`
							}
							if err := xml.Unmarshal(rec.Body.Bytes(), &result); err != nil || result.UploadID == "" {
								t.Fatal("missing multipart upload ID")
							}
							if err := obj.AbortMultipartUpload(t.Context(), bucket, "destination", result.UploadID, ObjectOptions{}); err != nil {
								t.Fatal(err)
							}
						}
					})
				}
			}
		}
	}})
}

func TestAPIRepairMultipartCompleteTags(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
		globalBucketMetadataSys.Set(bucket, newBucketMetadata(bucket))
		user := newTaggingTestUser(t)
		for _, requireRequestTags := range []bool{false, true} {
			for _, stored := range []string{"", "test=old"} {
				t.Run(fmt.Sprintf("%s/request-tags=%t/%s", instance, requireRequestTags, stored), func(t *testing.T) {
					repairTagFixture(t, obj, bucket, "complete", stored, false)
					condition := `"s3:ExistingObjectTag/test":"old"`
					if requireRequestTags {
						condition = `"s3:RequestObjectTag/test":"new"`
					}
					setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(`{"Effect":"Allow","Action":"s3:PutObject*","Resource":"arn:aws:s3:::%s/complete","Condition":{"StringEquals":{%s}}}`, bucket, condition))
					upload, err := obj.NewMultipartUpload(t.Context(), bucket, "complete", ObjectOptions{UserDefined: map[string]string{xhttp.AmzObjectTagging: "test=initialized"}})
					if err != nil {
						t.Fatal(err)
					}
					defer obj.AbortMultipartUpload(t.Context(), bucket, "complete", upload.UploadID, ObjectOptions{})
					part, err := obj.PutObjectPart(t.Context(), bucket, "complete", upload.UploadID, 1, mustGetPutObjReader(t, strings.NewReader("data"), 4, "", ""), ObjectOptions{})
					if err != nil {
						t.Fatal(err)
					}
					body := "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>" + part.ETag + "</ETag></Part></CompleteMultipartUpload>"
					header := http.Header{}
					header.Set(xhttp.AmzObjectTagging, "test=new")
					query := url.Values{"uploadId": {upload.UploadID}, "RequestObjectTag/test": {"new"}}
					rec := existingTagsTestRequest(t, router, http.MethodPost, getGetObjectURL("", bucket, "complete")+"?"+query.Encode(), body, header, user)
					want := http.StatusForbidden
					if !requireRequestTags && stored == "test=old" {
						want = http.StatusOK
					}
					if rec.Code != want {
						t.Errorf("HTTP %d, want %d", rec.Code, want)
					}
					if rec.Code == http.StatusOK && want == rec.Code {
						got, err := obj.GetObjectTags(t.Context(), bucket, "complete", ObjectOptions{})
						if err != nil || got.String() != "test=initialized" {
							t.Error("complete did not retain initiation tags")
						}
					}
				})
			}
		}
	}})
}

func TestAPIRepairAuthorizationOrdering(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
		globalBucketMetadataSys.Set(bucket, newBucketMetadata(bucket))
		user := newTaggingTestUser(t)
		setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(`{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::%s/destination"}`, bucket))
		repairTagFixture(t, obj, bucket, "marker", "test=old", true)
		marker, err := obj.DeleteObject(t.Context(), bucket, "marker", ObjectOptions{Versioned: true})
		if err != nil || marker.VersionID == "" || !marker.DeleteMarker {
			t.Fatal("missing marker fixture")
		}
		for _, source := range []string{
			"/" + bucket + "/absent", "/absent-bucket/source",
			"/" + bucket + "/marker", "/" + bucket + "/marker?versionId=" + marker.VersionID,
			"/" + bucket + "/marker?versionId=722fd0e1-43e4-4895-a2fc-1bd0033d7480",
		} {
			for _, part := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/source=%s/part=%t", instance, strings.SplitN(source, "?", 2)[0], part), func(t *testing.T) {
					header := http.Header{}
					header.Set(xhttp.AmzCopySource, source)
					target := getGetObjectURL("", bucket, "destination")
					if part {
						upload, err := obj.NewMultipartUpload(t.Context(), bucket, "destination", ObjectOptions{})
						if err != nil {
							t.Fatal(err)
						}
						defer obj.AbortMultipartUpload(t.Context(), bucket, "destination", upload.UploadID, ObjectOptions{})
						target += "?partNumber=1&uploadId=" + upload.UploadID
					}
					rec := existingTagsTestRequest(t, router, http.MethodPut, target, "", header, user)
					if rec.Code != http.StatusForbidden {
						t.Errorf("HTTP %d, want 403", rec.Code)
					}
					if rec.Header().Get(xhttp.AmzVersionID) != "" || rec.Header().Get(xhttp.AmzDeleteMarker) != "" {
						t.Error("source marker headers disclosed before source authorization")
					}
				})
			}
		}
		rec := existingTagsTestRequest(t, router, http.MethodDelete, "/absent-bucket/object", "", nil, user)
		if rec.Code != http.StatusForbidden {
			t.Errorf("missing-bucket DELETE HTTP %d, want 403", rec.Code)
		}
		// A conditional grant does not authorize a marker using client tags.
		setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(`{"Effect":"Allow","Action":["s3:GetObject*","s3:DeleteObject*"],"Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"old"}}}`, bucket))
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodDelete} {
			header := http.Header{}
			header.Set(xhttp.AmzObjectTagging, "test=old")
			target := getGetObjectURL("", bucket, "marker") + "?versionId=" + marker.VersionID + "&ExistingObjectTag%2Ftest=old"
			rec := existingTagsTestRequest(t, router, method, target, "", header, user)
			if rec.Code != http.StatusForbidden {
				t.Errorf("conditional marker %s HTTP %d, want 403", method, rec.Code)
			}
		}
	}})
}

func TestAPIRepairBulkVersionTags(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
		globalBucketMetadataSys.Set(bucket, newBucketMetadata(bucket))
		user := newTaggingTestUser(t)
		setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(`{"Effect":"Allow","Action":"s3:DeleteObject*","Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"old"}}}`, bucket))
		for _, identity := range []auth.Credentials{user, auth.AnonymousCredentials} {
			allowed := repairTagFixture(t, obj, bucket, "bulk-version", "test=old", true)
			denied := repairTagFixture(t, obj, bucket, "bulk-version", "", true)
			header := http.Header{}
			header.Set(xhttp.AmzObjectTagging, "test=old")
			body := "<Delete><Object><Key>bulk-version</Key><VersionId>" + allowed.VersionID + "</VersionId></Object><Object><Key>bulk-version</Key><VersionId>" + denied.VersionID + "</VersionId></Object></Delete>"
			rec := existingTagsTestRequest(t, router, http.MethodPost, "/"+bucket+"?delete&ExistingObjectTag%2Ftest=old", body, header, identity)
			if rec.Code != http.StatusOK {
				t.Errorf("%s HTTP %d, want 200", instance, rec.Code)
				continue
			}
			var result struct {
				Deleted []struct {
					VersionID string `xml:"VersionId"`
				} `xml:"Deleted"`
				Errors []struct {
					VersionID string `xml:"VersionId"`
					Code      string
				} `xml:"Error"`
			}
			if err := xml.Unmarshal(rec.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if len(result.Deleted) != 1 || result.Deleted[0].VersionID != allowed.VersionID || len(result.Errors) != 1 || result.Errors[0].VersionID != denied.VersionID || result.Errors[0].Code != "AccessDenied" {
				t.Error("bulk delete did not independently authorize the selected versions")
			}
		}
	}})
}

func TestAPIRepairRetentionAndBypassTags(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
		meta := newBucketMetadata(bucket)
		meta.objectLockConfig = &objectlock.Config{ObjectLockEnabled: objectlock.Enabled}
		globalBucketMetadataSys.Set(bucket, meta)
		user := newTaggingTestUser(t)
		for _, operation := range []string{"retention", "retention-bypass", "legal-hold", "bypass", "bulk-bypass"} {
			statements := fmt.Sprintf(`{"Effect":"Allow","Action":"s3:PutObject*","Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"old"}}}`, bucket)
			if operation == "bypass" || operation == "bulk-bypass" {
				statements = fmt.Sprintf(`{"Effect":"Allow","Action":"s3:DeleteObject*","Resource":"arn:aws:s3:::%s/*"},
				{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"old"}}}`, bucket, bucket)
			}
			setTaggingTestPolicy(t, bucket, user, statements)
			for _, stored := range []string{"", "test=old", "test=new"} {
				t.Run(instance+"/"+operation+"/"+stored, func(t *testing.T) {
					until := UTCNow().Add(24 * time.Hour)
					info, err := obj.PutObject(t.Context(), bucket, "locked", mustGetPutObjReader(t, strings.NewReader("data"), 4, "", ""), ObjectOptions{
						Versioned: true, UserDefined: map[string]string{
							xhttp.AmzObjectTagging:                              stored,
							strings.ToLower(xhttp.AmzObjectLockMode):            "GOVERNANCE",
							strings.ToLower(xhttp.AmzObjectLockRetainUntilDate): until.Format(time.RFC3339),
						},
					})
					if err != nil {
						t.Fatal(err)
					}
					header := http.Header{}
					clientTags := "test=new"
					if stored == "" {
						clientTags = "test=old"
					}
					header.Set(xhttp.AmzObjectTagging, clientTags)
					header.Set(xhttp.AmzObjectLockBypassGovernance, "true")
					query := url.Values{xhttp.VersionID: {info.VersionID}}
					method, body, want := http.MethodPut, "", http.StatusOK
					switch operation {
					case "retention", "retention-bypass":
						query.Set("retention", "")
						body = "<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>" + until.Add(time.Hour).Format(time.RFC3339) + "</RetainUntilDate></Retention>"
						if operation == "retention-bypass" {
							body = strings.ReplaceAll(body, until.Add(time.Hour).Format(time.RFC3339), until.Add(-time.Hour).Format(time.RFC3339))
						}
					case "legal-hold":
						query.Set("legal-hold", "")
						body = "<LegalHold><Status>ON</Status></LegalHold>"
					case "bypass":
						method, want = http.MethodDelete, http.StatusNoContent
					}
					if operation == "bulk-bypass" {
						body = "<Delete><Object><Key>locked</Key><VersionId>" + info.VersionID + "</VersionId></Object></Delete>"
						rec := existingTagsTestRequest(t, router, http.MethodPost, "/"+bucket+"?delete", body, header, user)
						var result struct {
							Deleted []struct{ Key string }  `xml:"Deleted"`
							Errors  []struct{ Code string } `xml:"Error"`
						}
						if err := xml.Unmarshal(rec.Body.Bytes(), &result); err != nil {
							t.Fatal(err)
						}
						if rec.Code != http.StatusOK || (stored == "test=old" && len(result.Deleted) != 1) ||
							(stored != "test=old" && (len(result.Errors) != 1 || result.Errors[0].Code != "AccessDenied")) {
							t.Error("bulk retention bypass ignored stored tags")
						}
						return
					}
					if stored != "test=old" {
						want = http.StatusForbidden
					}
					rec := existingTagsTestRequest(t, router, method, getGetObjectURL("", bucket, "locked")+"?"+query.Encode(), body, header, user)
					if rec.Code != want {
						t.Errorf("HTTP %d, want %d", rec.Code, want)
					}
				})
			}
		}
	}})
}

func TestAPIRepairLambdaOriginalHeaders(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
		globalBucketMetadataSys.Set(bucket, newBucketMetadata(bucket))
		user := newTaggingTestUser(t)
		setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"stored"}}}`, bucket))
		repairTagFixture(t, obj, bucket, "lambda-real", "test=stored", false)
		events := make(chan levent.Event, 2)
		remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead {
				return
			}
			if r.Method == http.MethodGet {
				w.Header().Set(xhttp.ContentType, "application/xml")
				_, _ = io.WriteString(w, "<LocationConstraint>us-east-1</LocationConstraint>")
				return
			}
			var event levent.Event
			if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
				t.Error("invalid event JSON")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			events <- event
			w.Header().Set(xhttp.AmzRequestRoute, event.GetObjectContext.OutputRoute)
			w.Header().Set(xhttp.AmzRequestToken, event.GetObjectContext.OutputToken)
			_, _ = io.WriteString(w, "data")
		}))
		defer remote.Close()
		cfg := config.New()
		cfg[config.LambdaWebhookSubSys] = map[string]config.KVS{"repair": {
			{Key: "endpoint", Value: remote.URL}, {Key: "enable", Value: config.EnableOn},
		}}
		previousTargets, previousNode, previousEndpoint := globalLambdaTargetList, globalLocalNodeName, globalMinioEndpointURL
		var err error
		globalLambdaTargetList, err = lambda.FetchEnabledTargets(t.Context(), cfg, http.DefaultTransport.(*http.Transport))
		if err != nil {
			t.Fatal(err)
		}
		globalLocalNodeName = strings.TrimPrefix(remote.URL, "http://")
		globalMinioEndpointURL, err = xnet.ParseURL(remote.URL)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			globalLambdaTargetList, globalLocalNodeName, globalMinioEndpointURL = previousTargets, previousNode, previousEndpoint
		}()
		for _, client := range []string{"", "test=client"} {
			header := http.Header{}
			if client != "" {
				header.Set(xhttp.AmzObjectTagging, client)
			}
			rec := existingTagsTestRequest(t, router, http.MethodGet, getGetObjectURL("", bucket, "lambda-real")+"?lambdaArn=arn:minio:s3-object-lambda::repair:webhook", "", header, user)
			if rec.Code != http.StatusOK {
				t.Errorf("%s lambda HTTP %d, want 200", instance, rec.Code)
				continue
			}
			select {
			case event := <-events:
				got := event.UserRequest.Headers.Get(xhttp.AmzObjectTagging)
				if got != client {
					t.Error("webhook received synthesized tags instead of original headers")
				}
				if event.GetObjectContext.InputS3URL == "" {
					t.Error("real event construction did not generate an input URL")
				}
			default:
				t.Error("no lambda event received")
			}
		}
	}})
}

// Both CopyObject and UploadPartCopy must authorize the selected source version,
// while the destination's tags and request tagging directive remain independent.
func TestAPIRepairCopyVersionTags(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
		globalBucketMetadataSys.Set(bucket, newBucketMetadata(bucket))
		user := newTaggingTestUser(t)
		for _, operation := range []string{"COPY", "REPLACE", "part"} {
			for _, stored := range []string{"", "test=source", "test=other"} {
				for _, identity := range []struct {
					name string
					cred auth.Credentials
				}{{"user", user}, {"anonymous", auth.AnonymousCredentials}} {
					t.Run(instance+"/"+operation+"/"+stored+"/"+identity.name, func(t *testing.T) {
						source := repairTagFixture(t, obj, bucket, "copy-source", stored, true)
						repairTagFixture(t, obj, bucket, "copy-source", "test=latest", true)
						repairTagFixture(t, obj, bucket, "copy-destination", "test=destination", false)
						requestCondition := `"Null":{"s3:RequestObjectTag/test":"true"}`
						if operation == "REPLACE" {
							requestCondition = `"StringEquals":{"s3:RequestObjectTag/test":"request"}`
						}
						setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(
							`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/copy-source","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"source","s3:versionid":"%s"}}},
							{"Effect":"Allow","Action":"s3:PutObject*","Resource":"arn:aws:s3:::%s/copy-destination","Condition":{"StringLike":{"s3:ExistingObjectTag/test":"destination"},%s}}`,
							bucket, source.VersionID, bucket, requestCondition))
						header := http.Header{}
						header.Set(xhttp.AmzCopySource, "/"+bucket+"/copy-source?versionId="+source.VersionID)
						header.Set(xhttp.AmzObjectTagging, "test=request")
						header.Set(xhttp.AmzTagDirective, operation)
						query := url.Values{"ExistingObjectTag/test": {"source"}, "RequestObjectTag/test": {"request"}, "versionid": {"forged"}}
						if operation == "part" {
							header.Del(xhttp.AmzTagDirective)
							upload, err := obj.NewMultipartUpload(t.Context(), bucket, "copy-destination", ObjectOptions{})
							if err != nil {
								t.Fatal(err)
							}
							defer obj.AbortMultipartUpload(t.Context(), bucket, "copy-destination", upload.UploadID, ObjectOptions{})
							query.Set("uploadId", upload.UploadID)
							query.Set("partNumber", "1")
						}
						rec := existingTagsTestRequest(t, router, http.MethodPut, getGetObjectURL("", bucket, "copy-destination")+"?"+query.Encode(), "", header, identity.cred)
						want := http.StatusForbidden
						if stored == "test=source" {
							want = http.StatusOK
						}
						if rec.Code != want {
							t.Errorf("HTTP %d, want %d", rec.Code, want)
						}
						if rec.Code == http.StatusOK && operation != "part" {
							info, err := obj.GetObjectInfo(t.Context(), bucket, "copy-destination", ObjectOptions{})
							expected := stored
							if operation == "REPLACE" {
								expected = "test=request"
							}
							if err != nil || info.UserTags != expected {
								t.Error("copy tagging directive changed stored tag semantics")
							}
						}
					})
				}
			}
		}
	}})
}

func TestAPIRepairTagKeysStayInNamespace(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
		globalBucketMetadataSys.Set(bucket, newBucketMetadata(bucket))
		user := newTaggingTestUser(t)
		for _, allowedUser := range []string{user.AccessKey, "impostor"} {
			setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(`{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::%s/object","Condition":{"StringEquals":{"aws:username":"%s"}}}`, bucket, allowedUser))
			header := http.Header{}
			header.Set(xhttp.AmzObjectTagging, "..%2Fusername=impostor")
			rec := existingTagsTestRequest(t, router, http.MethodPut, getGetObjectURL("", bucket, "object"), "data", header, user)
			want := http.StatusForbidden
			if allowedUser == user.AccessKey {
				want = http.StatusOK
			}
			if rec.Code != want {
				t.Errorf("%s tag key escaped its namespace: HTTP %d, want %d", instance, rec.Code, want)
			}
		}
	}})
}

func TestAPIRepairPostTagConditions(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
		globalBucketMetadataSys.Set(bucket, newBucketMetadata(bucket))
		user := newTaggingTestUser(t)
		for _, fanout := range []bool{false, true} {
			conditions := `"s3:ExistingObjectTag/test":"old","s3:RequestObjectTag/test":"new"`
			if fanout {
				conditions = `"s3:ExistingObjectTag/test":"old"`
			}
			setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(`{"Effect":"Allow","Action":"s3:PutObject*","Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{%s}}}`, bucket, conditions))
			for _, stored := range []string{"", "test=old", "test=other"} {
				t.Run(fmt.Sprintf("%s/fanout=%t/%s", instance, fanout, stored), func(t *testing.T) {
					repairTagFixture(t, obj, bucket, "post/upload.txt", stored, false)
					if fanout {
						repairTagFixture(t, obj, bucket, "post/upload.txt", "test=old", false)
						repairTagFixture(t, obj, bucket, "fanout-a", "test=old", false)
						repairTagFixture(t, obj, bucket, "fanout-b", stored, false)
					}
					now := UTCNow()
					document := buildGenericPolicy(now, user.AccessKey, "us-east-1", bucket, "post", false)
					var postPolicy map[string]any
					if err := json.Unmarshal(document, &postPolicy); err != nil {
						t.Fatal(err)
					}
					input := "<Tagging><TagSet><Tag><Key>test</Key><Value>new</Value></Tag></TagSet></Tagging>"
					postPolicy["conditions"] = append(postPolicy["conditions"].([]any), map[string]string{"tagging": input})
					document, err := json.Marshal(postPolicy)
					if err != nil {
						t.Fatal(err)
					}
					fields := map[string]string{"tagging": input}
					if fanout {
						fields["x-minio-fanout-list"] = "{\"key\":\"fanout-a\"}\n{\"key\":\"fanout-b\"}"
					}
					req, err := newPostRequestV4Generic("", bucket, "post", []byte("data"), user.AccessKey, user.SecretKey, "us-east-1", now, document, fields, false, false, false)
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set(xhttp.AmzObjectTagging, "test=old")
					rec := httptest.NewRecorder()
					router.ServeHTTP(rec, req)
					want := http.StatusForbidden
					if stored == "test=old" {
						want = http.StatusNoContent
						if fanout {
							want = http.StatusOK
						}
					}
					if rec.Code != want {
						t.Errorf("HTTP %d, want %d", rec.Code, want)
					}
				})
			}
		}
	}})
}

func TestAPIRepairOtherObjectActions(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
		globalBucketMetadataSys.Set(bucket, newBucketMetadata(bucket))
		user := newTaggingTestUser(t)
		setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(`{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{"s3:ExistingObjectTag/test":"old"}}}`, bucket))
		for _, operation := range []string{"part", "list-parts", "abort", "restore"} {
			for _, stored := range []string{"", "test=old", "test=other"} {
				for _, client := range []string{"test=old", "test=other"} {
					t.Run(instance+"/"+operation+"/"+stored+"/"+client, func(t *testing.T) {
						repairTagFixture(t, obj, bucket, "other-actions", stored, false)
						header := http.Header{}
						header.Set(xhttp.AmzObjectTagging, client)
						query := url.Values{"ExistingObjectTag/test": {"old"}, "RequestObjectTag/test": {"old"}}
						method, body, want := http.MethodPut, "data", http.StatusOK
						if operation == "restore" {
							method, body, want = http.MethodPost, "<RestoreRequest><Days>1</Days></RestoreRequest>", http.StatusForbidden
							query.Set("restore", "")
						} else {
							upload, err := obj.NewMultipartUpload(t.Context(), bucket, "other-actions", ObjectOptions{})
							if err != nil {
								t.Fatal(err)
							}
							defer obj.AbortMultipartUpload(t.Context(), bucket, "other-actions", upload.UploadID, ObjectOptions{})
							query.Set("uploadId", upload.UploadID)
							switch operation {
							case "part":
								query.Set("partNumber", "1")
							case "list-parts":
								method, body = http.MethodGet, ""
							case "abort":
								method, body, want = http.MethodDelete, "", http.StatusNoContent
							}
						}
						if stored != "test=old" {
							want = http.StatusForbidden
						}
						rec := existingTagsTestRequest(t, router, method, getGetObjectURL("", bucket, "other-actions")+"?"+query.Encode(), body, header, user)
						if rec.Code != want {
							var response APIErrorResponse
							_ = xml.Unmarshal(rec.Body.Bytes(), &response)
							t.Errorf("HTTP %d (%s), want %d", rec.Code, response.Code, want)
						}
						if operation == "restore" {
							var response APIErrorResponse
							expectedCode := "AccessDenied"
							if stored == "test=old" {
								expectedCode = "InvalidObjectState"
							}
							if err := xml.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.Code != expectedCode {
								t.Error("restore did not authorize before checking object state")
							}
						}
					})
				}
			}
		}
	}})
}

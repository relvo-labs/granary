// Copyright (c) 2026 Granary contributors.
//
// This file is part of Granary, an unofficial fork derived from MinIO.
// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/minio/pkg/v3/policy/condition"
	"github.com/relvo-labs/granary/internal/auth"
	objectlock "github.com/relvo-labs/granary/internal/bucket/object/lock"
	xhttp "github.com/relvo-labs/granary/internal/http"
)

func objectLockTestBucket(bucket string, enabled bool) {
	meta := newBucketMetadata(bucket)
	if enabled {
		meta.objectLockConfig = &objectlock.Config{ObjectLockEnabled: objectlock.Enabled}
	}
	globalBucketMetadataSys.Set(bucket, meta)
}

func apiErrorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct{ Code string }
	if rec.Body.Len() > 0 {
		if err := xml.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("invalid error XML: %v", err)
		}
	}
	return body.Code
}

// Reading legal hold or retention must authorize before revealing whether the
// bucket has object lock enabled, as the upstream handlers did.
func TestAPIObjectLockReadsAuthorizeFirst(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
		user := newTaggingTestUser(t)
		for _, lockEnabled := range []bool{false, true} {
			objectLockTestBucket(bucket, lockEnabled)
			repairTagFixture(t, obj, bucket, "lock-read", "test=value", lockEnabled)
			for _, operation := range []string{"retention", "legal-hold"} {
				for _, object := range []string{"lock-read", "absent"} {
					// Neither identity holds GetObjectRetention or GetObjectLegalHold.
					setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(`{"Effect":"Allow","Action":"s3:GetObjectTagging","Resource":"arn:aws:s3:::%s/*"}`, bucket))
					for _, identity := range []struct {
						name string
						cred auth.Credentials
					}{{"user", user}, {"anonymous", auth.AnonymousCredentials}} {
						t.Run(fmt.Sprintf("%s/lock=%t/%s/%s/%s", instance, lockEnabled, operation, object, identity.name), func(t *testing.T) {
							rec := existingTagsTestRequest(t, router, http.MethodGet, getGetObjectURL("", bucket, object)+"?"+operation, "", nil, identity.cred)
							if rec.Code != http.StatusForbidden || apiErrorCode(t, rec) != "AccessDenied" {
								t.Errorf("HTTP %d %q, want 403 AccessDenied", rec.Code, apiErrorCode(t, rec))
							}
						})
					}
				}
				if lockEnabled {
					continue
				}
				// An authorized caller still learns that the bucket lacks object lock,
				// for existing and missing objects alike.
				setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(`{"Effect":"Allow","Action":["s3:GetObjectRetention","s3:GetObjectLegalHold"],"Resource":"arn:aws:s3:::%s/*"}`, bucket))
				for _, object := range []string{"lock-read", "absent"} {
					t.Run(fmt.Sprintf("%s/authorized/%s/%s", instance, operation, object), func(t *testing.T) {
						rec := existingTagsTestRequest(t, router, http.MethodGet, getGetObjectURL("", bucket, object)+"?"+operation, "", nil, user)
						if rec.Code != http.StatusBadRequest || apiErrorCode(t, rec) != "InvalidRequest" {
							t.Errorf("HTTP %d %q, want 400 InvalidRequest", rec.Code, apiErrorCode(t, rec))
						}
					})
				}
			}
		}
	}})
}

func contentSHA256TestRequest(t *testing.T, router http.Handler, target string, presigned bool, forgedHeader string, cred auth.Credentials) *httptest.ResponseRecorder {
	t.Helper()
	req, err := newTestRequest(http.MethodGet, target, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if presigned {
		req.Header.Del(xhttp.AmzContentSha256)
		if err = preSignV4(req, cred.AccessKey, cred.SecretKey, 60); err != nil {
			t.Fatal(err)
		}
		if forgedHeader != "" {
			// Presigned requests sign only the host header.
			req.Header.Set(xhttp.AmzContentSha256, forgedHeader)
		}
	} else if err = signRequestV4(req, cred.AccessKey, cred.SecretKey); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// s3:x-amz-content-sha256 must keep the value the signature verifier used,
// including the query-string form carried by presigned requests.
func TestAPIContentSHA256ConditionPreserved(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
		globalBucketMetadataSys.Set(bucket, newBucketMetadata(bucket))
		user := newTaggingTestUser(t)
		repairTagFixture(t, obj, bucket, "sha-object", "", false)
		target := getGetObjectURL("", bucket, "sha-object")
		for _, tc := range []struct {
			name, allowed, forgedHeader string
			presigned                   bool
			want                        int
		}{
			{name: "presigned", allowed: unsignedPayload, presigned: true, want: http.StatusOK},
			{name: "presigned-other", allowed: emptySHA256, presigned: true, want: http.StatusForbidden},
			{name: "presigned-unsigned-header", allowed: "forged", forgedHeader: "forged", presigned: true, want: http.StatusForbidden},
			{name: "header", allowed: emptySHA256, want: http.StatusOK},
			{name: "header-other", allowed: unsignedPayload, want: http.StatusForbidden},
		} {
			t.Run(instance+"/"+tc.name, func(t *testing.T) {
				setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{"s3:x-amz-content-sha256":"%s"}}}`, bucket, tc.allowed))
				rec := contentSHA256TestRequest(t, router, target, tc.presigned, tc.forgedHeader, user)
				if rec.Code != tc.want {
					t.Errorf("HTTP %d %q, want %d", rec.Code, apiErrorCode(t, rec), tc.want)
				}
			})
		}
	}})
}

// Reserved keys are dropped from raw import, but their server-derived values
// must still reach policy evaluation.
func TestReservedConditionValuesRetained(t *testing.T) {
	until := "2030-01-01T00:00:00Z"
	req := httptest.NewRequest(http.MethodPut, "http://localhost/bucket/object?versionId=v1", nil)
	req.Form = url.Values{xhttp.VersionID: {"v1"}}
	req.Header.Set(xhttp.AmzObjectLockMode, "GOVERNANCE")
	req.Header.Set(xhttp.AmzObjectLockLegalHold, "ON")
	req.Header.Set(xhttp.AmzObjectLockRetainUntilDate, until)
	req.Header.Set(xhttp.AmzContentSha256, emptySHA256)
	req = req.WithContext(context.WithValue(req.Context(), signatureAgeContextKey{}, "42"))
	values := getConditionValues(req, "us-east-1", auth.Credentials{AccessKey: "fixture-user"})
	for key, want := range map[condition.KeyName]string{
		condition.S3VersionID:                 "v1",
		condition.S3ObjectLockMode:            "GOVERNANCE",
		condition.S3ObjectLockLegalHold:       "ON",
		condition.S3ObjectLockRetainUntilDate: until,
		condition.S3XAmzContentSha256:         emptySHA256,
		condition.S3SignatureAge:              "42",
		condition.S3LocationConstraint:        "us-east-1",
		condition.AWSUsername:                 "fixture-user",
	} {
		got := values[http.CanonicalHeaderKey(key.Name())]
		if got == nil {
			got = values[key.Name()]
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

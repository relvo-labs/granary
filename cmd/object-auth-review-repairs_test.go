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

type contentSHA256TestCase struct {
	name, allowed string
	presigned     bool
	// forgedHeader is set after presigning; presigned requests sign only host.
	forgedHeader string
	// appendedHash is added to the presigned query after signing.
	appendedHash string
	// headerHashes are sent (and signed) in order on a header-signed request.
	headerHashes []string
	want         int
}

func contentSHA256TestRequest(t *testing.T, router http.Handler, target string, tc contentSHA256TestCase, cred auth.Credentials) *httptest.ResponseRecorder {
	t.Helper()
	req, err := newTestRequest(http.MethodGet, target, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tc.presigned {
		req.Header.Del(xhttp.AmzContentSha256)
		if err = preSignV4(req, cred.AccessKey, cred.SecretKey, 60); err != nil {
			t.Fatal(err)
		}
		if tc.forgedHeader != "" {
			req.Header.Set(xhttp.AmzContentSha256, tc.forgedHeader)
		}
		if tc.appendedHash != "" {
			req.URL.RawQuery += "&" + url.Values{xhttp.AmzContentSha256: {tc.appendedHash}}.Encode()
		}
	} else {
		if len(tc.headerHashes) > 0 {
			req.Header[xhttp.AmzContentSha256] = tc.headerHashes
		}
		if err = signRequestV4(req, cred.AccessKey, cred.SecretKey); err != nil {
			t.Fatal(err)
		}
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
		for _, tc := range []contentSHA256TestCase{
			{name: "presigned", allowed: unsignedPayload, presigned: true, want: http.StatusOK},
			{name: "presigned-other", allowed: emptySHA256, presigned: true, want: http.StatusForbidden},
			{name: "presigned-unsigned-header", allowed: "forged", forgedHeader: "forged", presigned: true, want: http.StatusForbidden},
			// The verifier signs and checks only the first query value, so a
			// value appended to a presigned URL must not satisfy the policy.
			{name: "presigned-appended-allowed", allowed: emptySHA256, appendedHash: emptySHA256, presigned: true, want: http.StatusForbidden},
			{name: "presigned-appended-other", allowed: unsignedPayload, appendedHash: emptySHA256, presigned: true, want: http.StatusOK},
			{name: "header", allowed: emptySHA256, want: http.StatusOK},
			{name: "header-other", allowed: unsignedPayload, want: http.StatusForbidden},
			// Header-signed payload verification also uses only the first value.
			{name: "header-duplicate-second", allowed: unsignedPayload, headerHashes: []string{emptySHA256, unsignedPayload}, want: http.StatusForbidden},
			{name: "header-duplicate-first", allowed: emptySHA256, headerHashes: []string{emptySHA256, unsignedPayload}, want: http.StatusOK},
		} {
			t.Run(instance+"/"+tc.name, func(t *testing.T) {
				setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*","Condition":{"StringEquals":{"s3:x-amz-content-sha256":"%s"}}}`, bucket, tc.allowed))
				rec := contentSHA256TestRequest(t, router, target, tc, user)
				var code string
				if rec.Code >= http.StatusMultipleChoices {
					code = apiErrorCode(t, rec)
				}
				if rec.Code != tc.want || (tc.want == http.StatusForbidden && code != "AccessDenied") {
					t.Errorf("HTTP %d %q, want %d", rec.Code, code, tc.want)
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

// Only the payload hash the SigV4 verifier selected may reach policy
// evaluation; later duplicates are neither signed nor checked against the body.
func TestContentSHA256ConditionSingleValue(t *testing.T) {
	for _, tc := range []struct {
		name   string
		query  url.Values
		header []string
		want   []string
	}{
		{name: "presigned-query", query: url.Values{xhttp.AmzCredential: {"c"}, xhttp.AmzContentSha256: {unsignedPayload, emptySHA256}}, header: []string{emptySHA256}, want: []string{unsignedPayload}},
		{name: "presigned-header-fallback", query: url.Values{xhttp.AmzCredential: {"c"}}, header: []string{emptySHA256, unsignedPayload}, want: []string{emptySHA256}},
		{name: "header", query: url.Values{xhttp.AmzContentSha256: {unsignedPayload}}, header: []string{emptySHA256, unsignedPayload}, want: []string{emptySHA256}},
		{name: "absent", query: url.Values{xhttp.AmzCredential: {"c"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost/bucket/object?"+tc.query.Encode(), nil)
			req.Form = tc.query
			if tc.header != nil {
				req.Header[xhttp.AmzContentSha256] = tc.header
			}
			values := getConditionValues(req, "", auth.Credentials{AccessKey: "fixture-user"})
			name := condition.S3XAmzContentSha256.Name()
			canonical := values[http.CanonicalHeaderKey(name)]
			got := make([]string, 0, len(canonical)+len(values[name]))
			got = append(got, canonical...)
			got = append(got, values[name]...)
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("x-amz-content-sha256 = %q, want %q", got, tc.want)
			}
		})
	}
}

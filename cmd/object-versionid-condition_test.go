// Copyright (c) 2026 Granary contributors.
//
// This file is part of Granary, an unofficial fork derived from MinIO.
// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/relvo-labs/granary/internal/auth"
	xhttp "github.com/relvo-labs/granary/internal/http"
)

// s3:versionid must describe the version the request selects. An unrelated
// X-Amz-Copy-Source header on GET/HEAD must not supply it (issue #67).
func TestAPIVersionIDConditionIgnoresCopySourceOnRead(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
		globalBucketMetadataSys.Set(bucket, newBucketMetadata(bucket))
		user := newTaggingTestUser(t)
		v1 := repairTagFixture(t, obj, bucket, "versioned", "", true)
		repairTagFixture(t, obj, bucket, "versioned", "", true)
		setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/versioned","Condition":{"StringEquals":{"s3:versionid":"%s"}}}`, bucket, v1.VersionID))
		for _, identity := range []struct {
			name string
			cred auth.Credentials
		}{{"user", user}, {"anonymous", auth.AnonymousCredentials}} {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				for _, tc := range []struct {
					name, query, copySource string
					want                    int
				}{
					{name: "forged-copy-source", copySource: "/x/versioned?versionId=" + v1.VersionID, want: http.StatusForbidden},
					{name: "forged-copy-source-same-bucket", copySource: "/" + bucket + "/versioned?versionId=" + v1.VersionID, want: http.StatusForbidden},
					{name: "latest", want: http.StatusForbidden},
					{name: "selected", query: v1.VersionID, want: http.StatusOK},
					{name: "selected-with-copy-source", query: v1.VersionID, copySource: "/x/versioned?versionId=other", want: http.StatusOK},
				} {
					t.Run(instance+"/"+identity.name+"/"+method+"/"+tc.name, func(t *testing.T) {
						target := getGetObjectURL("", bucket, "versioned")
						if tc.query != "" {
							target += "?" + url.Values{xhttp.VersionID: {tc.query}}.Encode()
						}
						header := http.Header{}
						if tc.copySource != "" {
							header.Set(xhttp.AmzCopySource, tc.copySource)
						}
						rec := existingTagsTestRequest(t, router, method, target, "", header, identity.cred)
						if rec.Code != tc.want {
							t.Errorf("HTTP %d, want %d", rec.Code, tc.want)
						}
					})
				}
			}
		}
	}})
}

// CopyObject and UploadPartCopy authorize the source with the version named
// in X-Amz-Copy-Source; removing the general fallback must keep that working.
func TestAPIVersionIDConditionCopySource(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
		globalBucketMetadataSys.Set(bucket, newBucketMetadata(bucket))
		user := newTaggingTestUser(t)
		v1 := repairTagFixture(t, obj, bucket, "copy-versioned", "", true)
		v2 := repairTagFixture(t, obj, bucket, "copy-versioned", "", true)
		setTaggingTestPolicy(t, bucket, user, fmt.Sprintf(
			`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/copy-versioned","Condition":{"StringEquals":{"s3:versionid":"%s"}}},
			{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::%s/copy-target"}`,
			bucket, v1.VersionID, bucket))
		for _, identity := range []struct {
			name string
			cred auth.Credentials
		}{{"user", user}, {"anonymous", auth.AnonymousCredentials}} {
			for _, part := range []bool{false, true} {
				for _, tc := range []struct {
					name, source string
					want         int
				}{
					{name: "selected", source: "?versionId=" + v1.VersionID, want: http.StatusOK},
					{name: "other", source: "?versionId=" + v2.VersionID, want: http.StatusForbidden},
					{name: "latest", want: http.StatusForbidden},
				} {
					t.Run(fmt.Sprintf("%s/%s/part=%t/%s", instance, identity.name, part, tc.name), func(t *testing.T) {
						target := getGetObjectURL("", bucket, "copy-target")
						if part {
							upload, err := obj.NewMultipartUpload(t.Context(), bucket, "copy-target", ObjectOptions{})
							if err != nil {
								t.Fatal(err)
							}
							defer obj.AbortMultipartUpload(t.Context(), bucket, "copy-target", upload.UploadID, ObjectOptions{})
							target += "?" + url.Values{"partNumber": {"1"}, "uploadId": {upload.UploadID}}.Encode()
						}
						header := http.Header{}
						header.Set(xhttp.AmzCopySource, "/"+bucket+"/copy-versioned"+tc.source)
						rec := existingTagsTestRequest(t, router, http.MethodPut, target, "", header, identity.cred)
						if rec.Code != tc.want {
							t.Errorf("HTTP %d %q, want %d", rec.Code, apiErrorCode(t, rec), tc.want)
						}
					})
				}
			}
		}
	}})
}

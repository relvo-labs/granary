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

package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/pkg/v3/policy"
	"github.com/relvo-labs/granary/internal/auth"
	"github.com/relvo-labs/granary/internal/bucket/replication"
	"github.com/relvo-labs/granary/internal/crypto"
	xhttp "github.com/relvo-labs/granary/internal/http"
)

// Regression tests for GHSA-3rh2-v3gr-35p9 / CVE-2026-34204 (issue #72):
// replication-only SSE headers must never become internal object metadata
// unless the request is an authorized replication request.

var (
	sseReplTestSealedKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xab}, 64))
	sseReplTestIV        = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xcd}, 32))
	sseReplTestChecksum  = []byte("granary-issue-72-bogus-checksum")
)

// sseReplTestHeaders returns every replication-only header that is mapped to
// internal metadata by extractMetadataFromMime.
func sseReplTestHeaders() map[string]string {
	return map[string]string{
		"X-Minio-Replication-Server-Side-Encryption-Sealed-Key":     sseReplTestSealedKey,
		"X-Minio-Replication-Server-Side-Encryption-Seal-Algorithm": crypto.SealAlgorithm,
		"X-Minio-Replication-Server-Side-Encryption-Iv":             sseReplTestIV,
		"X-Minio-Replication-Encrypted-Multipart":                   "true",
		xhttp.MinIOReplicationActualObjectSize:                      "4242",
		ReplicationSsecChecksumHeader:                               base64.StdEncoding.EncodeToString(sseReplTestChecksum),
	}
}

var sseReplTestInternalKeys = []string{
	"X-Minio-Internal-Server-Side-Encryption-Sealed-Key",
	"X-Minio-Internal-Server-Side-Encryption-Seal-Algorithm",
	"X-Minio-Internal-Server-Side-Encryption-Iv",
	"X-Minio-Internal-Encrypted-Multipart",
	"X-Minio-Internal-Actual-Object-Size",
	ReplicationSsecChecksumHeader,
}

func sseReplTestLookup(m map[string]string, key string) (string, bool) {
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

func assertNoInjectedSSEMetadata(t *testing.T, oi ObjectInfo) {
	t.Helper()
	for _, key := range sseReplTestInternalKeys {
		if v, ok := sseReplTestLookup(oi.UserDefined, key); ok {
			t.Errorf("unauthorized request stored internal metadata %s=%q", key, v)
		}
	}
	if v, _ := sseReplTestLookup(oi.UserDefined, ReservedMetadataPrefix+"actual-size"); v == "4242" {
		t.Errorf("unauthorized request stored injected actual size %q", v)
	}
	if kind, ok := crypto.IsEncrypted(oi.UserDefined); ok {
		t.Errorf("unauthorized request marked object as %v encrypted", kind)
	}
	if bytes.Equal(oi.Checksum, sseReplTestChecksum) {
		t.Errorf("unauthorized request stored injected checksum")
	}
}

func assertSSEReplicationMetadata(t *testing.T, userDefined map[string]string) {
	t.Helper()
	if v, _ := sseReplTestLookup(userDefined, "X-Minio-Internal-Server-Side-Encryption-Sealed-Key"); v != sseReplTestSealedKey {
		t.Errorf("authorized replication sealed key = %q, want %q", v, sseReplTestSealedKey)
	}
	if v, _ := sseReplTestLookup(userDefined, "X-Minio-Internal-Server-Side-Encryption-Iv"); v != sseReplTestIV {
		t.Errorf("authorized replication IV = %q, want %q", v, sseReplTestIV)
	}
	if v, _ := sseReplTestLookup(userDefined, "X-Minio-Internal-Server-Side-Encryption-Seal-Algorithm"); v != crypto.SealAlgorithm {
		t.Errorf("authorized replication seal algorithm = %q", v)
	}
	if _, ok := sseReplTestLookup(userDefined, "X-Minio-Internal-Encrypted-Multipart"); !ok {
		t.Errorf("authorized replication encrypted-multipart marker missing")
	}
}

func newSSEReplTestUser(t *testing.T, bucket string, actions ...string) auth.Credentials {
	t.Helper()
	cred, err := auth.GetNewCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = globalIAMSys.CreateUser(t.Context(), cred.AccessKey, madmin.AddOrUpdateUserReq{
		SecretKey: cred.SecretKey, Status: madmin.AccountEnabled,
	}); err != nil {
		t.Fatal(err)
	}
	quoted := make([]string, len(actions))
	for i, a := range actions {
		quoted[i] = fmt.Sprintf("%q", a)
	}
	config := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":[%s],"Resource":["arn:aws:s3:::%s","arn:aws:s3:::%s/*"]}]}`,
		strings.Join(quoted, ","), bucket, bucket)
	p, err := policy.ParseConfig(strings.NewReader(config))
	if err != nil {
		t.Fatal(err)
	}
	name := "sse-repl-test-" + strings.ToLower(cred.AccessKey)
	if _, err = globalIAMSys.SetPolicy(t.Context(), name, *p); err != nil {
		t.Fatal(err)
	}
	if _, err = globalIAMSys.PolicyDBSet(t.Context(), cred.AccessKey, name, regUser, false); err != nil {
		t.Fatal(err)
	}
	return cred
}

func sseReplTestDo(t *testing.T, router http.Handler, method, target string, body []byte, cred auth.Credentials, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req, err := newTestSignedRequestV4(method, target, int64(len(body)), bytes.NewReader(body), cred.AccessKey, cred.SecretKey, headers)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func sseReplTestMerge(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

var (
	sseReplSourceFlag = map[string]string{xhttp.MinIOSourceReplicationRequest: "true"}
	sseReplReplica    = map[string]string{xhttp.AmzBucketReplicationStatus: replication.Replica.String()}
)

// TestExtractMetadataIgnoresSSEReplicationHeaders covers every caller that
// extracts metadata from client-controlled headers or form fields (PUT,
// POST policy, copy REPLACE, multipart init and PutObjectExtract records).
func TestExtractMetadataIgnoresSSEReplicationHeaders(t *testing.T) {
	h := textproto.MIMEHeader{}
	for k, v := range sseReplTestHeaders() {
		h.Set(k, v)
	}
	h.Set(xhttp.MinIOSourceReplicationRequest, "true")
	h.Set(xhttp.AmzBucketReplicationStatus, replication.Replica.String())
	m, err := extractMetadata(t.Context(), h)
	if err != nil {
		t.Fatal(err)
	}
	assertNoInjectedSSEMetadata(t, ObjectInfo{UserDefined: m})
	for k := range sseReplTestHeaders() {
		if v, ok := sseReplTestLookup(m, k); ok {
			t.Errorf("replication header %s=%q kept as metadata", k, v)
		}
	}
}

func TestAPIPutObjectSSEReplicationHeaders(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testAPIPutObjectSSEReplicationHeaders})
}

func testAPIPutObjectSSEReplicationHeaders(obj ObjectLayer, instanceType, bucket string, router http.Handler, root auth.Credentials, t *testing.T) {
	regular := newSSEReplTestUser(t, bucket, "s3:PutObject")
	replicator := newSSEReplTestUser(t, bucket, "s3:PutObject", "s3:ReplicateObject")
	data := []byte("hello")

	cases := []struct {
		name       string
		cred       auth.Credentials
		headers    map[string]string
		wantStatus int
		wantMapped bool
	}{
		{"regular-user", regular, sseReplTestHeaders(), http.StatusOK, false},
		{"regular-user-source-flag", regular, sseReplTestMerge(sseReplTestHeaders(), sseReplSourceFlag), http.StatusOK, false},
		{"regular-user-replica", regular, sseReplTestMerge(sseReplTestHeaders(), sseReplSourceFlag, sseReplReplica), http.StatusForbidden, false},
		{"replicator-without-source-flag", replicator, sseReplTestMerge(sseReplTestHeaders(), sseReplReplica), http.StatusOK, false},
		{"replicator", replicator, sseReplTestMerge(sseReplTestHeaders(), sseReplSourceFlag, sseReplReplica), http.StatusOK, true},
		{"root-replication", root, sseReplTestMerge(sseReplTestHeaders(), sseReplSourceFlag, sseReplReplica), http.StatusOK, true},
	}
	for _, tc := range cases {
		t.Run(instanceType+"/"+tc.name, func(t *testing.T) {
			object := "put-" + tc.name
			rec := sseReplTestDo(t, router, http.MethodPut, getPutObjectURL("", bucket, object), data, tc.cred, tc.headers)
			if rec.Code != tc.wantStatus {
				t.Fatalf("HTTP %d, want %d: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			oi, err := obj.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{})
			if tc.wantStatus != http.StatusOK {
				if err == nil {
					t.Fatalf("rejected request stored an object")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantMapped {
				assertSSEReplicationMetadata(t, oi.UserDefined)
				return
			}
			assertNoInjectedSSEMetadata(t, oi)
		})
	}
}

func TestAPIMultipartSSEReplicationHeaders(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testAPIMultipartSSEReplicationHeaders})
}

type sseReplTestInitResult struct {
	UploadID string `xml:"UploadId"`
}

func testAPIMultipartSSEReplicationHeaders(obj ObjectLayer, instanceType, bucket string, router http.Handler, root auth.Credentials, t *testing.T) {
	regular := newSSEReplTestUser(t, bucket, "s3:PutObject")
	replicator := newSSEReplTestUser(t, bucket, "s3:PutObject", "s3:ReplicateObject")

	initUpload := func(t *testing.T, object string, cred auth.Credentials, headers map[string]string) string {
		t.Helper()
		rec := sseReplTestDo(t, router, http.MethodPost, getNewMultipartURL("", bucket, object), nil, cred, headers)
		if rec.Code != http.StatusOK {
			t.Fatalf("initiate HTTP %d: %s", rec.Code, rec.Body.String())
		}
		var res sseReplTestInitResult
		if err := xml.Unmarshal(rec.Body.Bytes(), &res); err != nil || res.UploadID == "" {
			t.Fatalf("invalid initiate response %q: %v", rec.Body.String(), err)
		}
		return res.UploadID
	}

	// Multipart initiation.
	initCases := []struct {
		name       string
		cred       auth.Credentials
		headers    map[string]string
		wantMapped bool
	}{
		{"regular-user", regular, sseReplTestHeaders(), false},
		{"regular-user-source-flag", regular, sseReplTestMerge(sseReplTestHeaders(), sseReplSourceFlag), false},
		{"replicator", replicator, sseReplTestMerge(sseReplTestHeaders(), sseReplSourceFlag, sseReplReplica), true},
	}
	for _, tc := range initCases {
		t.Run(instanceType+"/init/"+tc.name, func(t *testing.T) {
			object := "mp-init-" + tc.name
			uploadID := initUpload(t, object, tc.cred, tc.headers)
			info, err := obj.GetMultipartInfo(t.Context(), bucket, object, uploadID, ObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantMapped {
				assertSSEReplicationMetadata(t, info.UserDefined)
				return
			}
			assertNoInjectedSSEMetadata(t, ObjectInfo{UserDefined: info.UserDefined})
		})
	}

	// Multipart completion.
	completeCases := []struct {
		name     string
		cred     auth.Credentials
		headers  map[string]string
		wantSize string
	}{
		{"regular-user-source-flag", regular, sseReplTestMerge(sseReplTestHeaders(), sseReplSourceFlag), ""},
		{"replicator", replicator, sseReplTestMerge(sseReplTestHeaders(), sseReplSourceFlag), "4242"},
	}
	for _, tc := range completeCases {
		t.Run(instanceType+"/complete/"+tc.name, func(t *testing.T) {
			object := "mp-complete-" + tc.name
			uploadID := initUpload(t, object, tc.cred, nil)
			part := []byte("hello")
			rec := sseReplTestDo(t, router, http.MethodPut, getPutObjectPartURL("", bucket, object, uploadID, "1"), part, tc.cred, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("part HTTP %d: %s", rec.Code, rec.Body.String())
			}
			// ETag is set with a non-canonical key, so Header.Get cannot find it.
			etag := strings.Trim(strings.Join(rec.Header()[xhttp.ETag], ""), `"`)
			body := fmt.Sprintf(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`, etag)
			rec = sseReplTestDo(t, router, http.MethodPost, getCompleteMultipartUploadURL("", bucket, object, uploadID), []byte(body), tc.cred, tc.headers)
			if rec.Code != http.StatusOK {
				t.Fatalf("complete HTTP %d: %s", rec.Code, rec.Body.String())
			}
			oi, err := obj.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantSize != "" {
				if v, _ := sseReplTestLookup(oi.UserDefined, ReservedMetadataPrefix+"actual-size"); v != tc.wantSize {
					t.Errorf("authorized replication actual size = %q, want %q", v, tc.wantSize)
				}
				if !bytes.Equal(oi.Checksum, sseReplTestChecksum) {
					t.Errorf("authorized replication checksum = %q, want %q", oi.Checksum, sseReplTestChecksum)
				}
				return
			}
			assertNoInjectedSSEMetadata(t, oi)
		})
	}
}

func TestAPICopyObjectSSEReplicationHeaders(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testAPICopyObjectSSEReplicationHeaders})
}

func testAPICopyObjectSSEReplicationHeaders(obj ObjectLayer, instanceType, bucket string, router http.Handler, root auth.Credentials, t *testing.T) {
	regular := newSSEReplTestUser(t, bucket, "s3:PutObject", "s3:GetObject")
	if _, err := obj.PutObject(t.Context(), bucket, "copy-source", mustGetPutObjReader(t, bytes.NewReader([]byte("hello")), 5, "", ""), ObjectOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"regular-user", "regular-user-source-flag"} {
		t.Run(instanceType+"/"+name, func(t *testing.T) {
			headers := sseReplTestMerge(sseReplTestHeaders(), map[string]string{
				xhttp.AmzCopySource:        url.QueryEscape(SlashSeparator + bucket + SlashSeparator + "copy-source"),
				xhttp.AmzMetadataDirective: replaceDirective,
			})
			if name == "regular-user-source-flag" {
				headers = sseReplTestMerge(headers, sseReplSourceFlag)
			}
			object := "copy-" + name
			rec := sseReplTestDo(t, router, http.MethodPut, getCopyObjectURL("", bucket, object), nil, regular, headers)
			if rec.Code != http.StatusOK {
				t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
			}
			oi, err := obj.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			assertNoInjectedSSEMetadata(t, oi)
		})
	}
}

func TestAPIPostPolicySSEReplicationHeaders(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testAPIPostPolicySSEReplicationHeaders})
}

func testAPIPostPolicySSEReplicationHeaders(obj ObjectLayer, instanceType, bucket string, router http.Handler, root auth.Credentials, t *testing.T) {
	regular := newSSEReplTestUser(t, bucket, "s3:PutObject")
	const objectName = "post-policy"
	now := UTCNow()
	region := globalSite.Region()
	credStr := getCredentialString(regular.AccessKey, region, now)
	form := sseReplTestMerge(sseReplTestHeaders(), sseReplSourceFlag)
	conds := []string{
		fmt.Sprintf(`["eq", "$bucket", %q]`, bucket),
		fmt.Sprintf(`["eq", "$key", %q]`, objectName+"/upload.txt"),
		`["eq", "$x-amz-algorithm", "AWS4-HMAC-SHA256"]`,
		fmt.Sprintf(`["eq", "$x-amz-date", %q]`, now.Format(iso8601DateFormat)),
		fmt.Sprintf(`["eq", "$x-amz-credential", %q]`, credStr),
		`["eq", "$x-amz-meta-uuid", "1234"]`,
		`["eq", "$content-encoding", "gzip"]`,
	}
	for k, v := range form {
		conds = append(conds, fmt.Sprintf(`["eq", "$%s", %q]`, k, v))
	}
	policyDoc := fmt.Sprintf(`{"expiration": %q, "conditions": [%s]}`,
		now.Add(5*time.Minute).Format(iso8601TimeFormat), strings.Join(conds, ", "))
	req, err := newPostRequestV4Generic("", bucket, objectName, []byte("hello"), regular.AccessKey, regular.SecretKey, region,
		now, []byte(policyDoc), form, false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("%s: HTTP %d: %s", instanceType, rec.Code, rec.Body.String())
	}
	oi, err := obj.GetObjectInfo(t.Context(), bucket, objectName+"/upload.txt", ObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertNoInjectedSSEMetadata(t, oi)
}

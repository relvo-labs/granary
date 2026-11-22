// Copyright (c) 2026 Granary contributors
//
// This file is part of Granary, an unofficial fork derived from MinIO.
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/minio/minio-go/v7/pkg/signer"
	"github.com/relvo-labs/granary/internal/auth"
	xhttp "github.com/relvo-labs/granary/internal/http"
)

// Extract must not acknowledge a streaming upload before its final chunk and
// trailer are verified. Padding after the tar terminator keeps the remaining
// framing unread by tar.Reader, so only an explicit drain can verify it.
func TestStreamingExtractVerifiesTerminal(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testStreamingExtractVerifiesTerminal})
}

func testStreamingExtractVerifiesTerminal(obj ObjectLayer, instance, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
	content := bytes.Repeat([]byte("x"), 8192)
	var archive bytes.Buffer
	tw := tar.NewWriter(&archive)
	if err := tw.WriteHeader(&tar.Header{Name: "entry", Mode: 0o600, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	const (
		unsignedTrailer = "unsigned-trailer"
		signedTrailer   = "signed-trailer"
		signedStreaming = "signed"
	)
	// 8 KiB padding stays in the archive's chunk; 128 KiB also leaves whole
	// signed data chunks unread after the tar terminator.
	for _, padding := range []int{0, 8192, 128 << 10} {
		payload := append(bytes.Clone(archive.Bytes()), make([]byte, padding)...)
		for _, mode := range []string{unsignedTrailer, signedTrailer, signedStreaming} {
			for _, tt := range []struct {
				name string
				want APIErrorCode
			}{
				{name: "complete"},
				{name: "truncated terminator", want: ErrIncompleteBody},
				{name: "missing final chunk", want: ErrIncompleteBody},
				{name: "bad checksum", want: ErrContentChecksumMismatch},
				{name: "bad final signature", want: ErrSignatureDoesNotMatch},
			} {
				hasTrailer := mode != signedStreaming
				if tt.name == "bad checksum" && !hasTrailer {
					continue
				}
				if tt.name == "bad final signature" && mode == unsignedTrailer {
					continue
				}
				t.Run(fmt.Sprintf("%s/%s/padding=%d/%s", instance, mode, padding, tt.name), func(t *testing.T) {
					prefix := fmt.Sprintf("extract-terminal-%s-%d-%s", mode, padding, tt.name)
					req, err := http.NewRequest(http.MethodPut, "http://localhost/"+bucket+"/"+prefix, bytes.NewReader(payload))
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set(xhttp.AmzSnowballExtract, "true")
					req.Header.Set(xhttp.MinIOSnowballPrefix, prefix)
					checksum := unsignedTrailerCRC(payload)
					if tt.name == "bad checksum" {
						checksum = "AAAAAA=="
					}
					trailer := http.Header{"X-Amz-Checksum-Crc32": {checksum}}
					switch mode {
					case unsignedTrailer:
						req.Header.Set(xhttp.AmzContentSha256, unsignedPayloadTrailer)
						req = signer.SignV4Trailer(*req, cred.AccessKey, cred.SecretKey, "", globalSite.Region(), trailer)
					default:
						req.Header.Set("Content-Encoding", "aws-chunked")
						if hasTrailer {
							req.Trailer = trailer
						}
						req = signer.StreamingSignV4(req, cred.AccessKey, cred.SecretKey, "", globalSite.Region(), int64(len(payload)), UTCNow(), trailerSHA256Hasher{sha256.New()})
					}
					wire, err := io.ReadAll(req.Body)
					req.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					wantSHA := map[string]string{
						unsignedTrailer: unsignedPayloadTrailer,
						signedTrailer:   streamingContentSHA256Trailer,
						signedStreaming: streamingContentSHA256,
					}[mode]
					if got := req.Header.Get(xhttp.AmzContentSha256); got != wantSHA {
						t.Fatalf("signer produced %q, want %q", got, wantSHA)
					}
					// Keep the declared wire and decoded lengths intact; only the
					// framing after the tar terminator is damaged.
					body := wire
					switch tt.name {
					case "truncated terminator":
						trim := 1
						if !hasTrailer {
							// The final CRLF after an untrailed zero chunk is
							// not read by any streaming path; cut its line.
							trim = 3
						}
						body = wire[:len(wire)-trim]
					case "missing final chunk":
						marker := []byte("\r\n0\r\n")
						offset := 2
						if mode != unsignedTrailer {
							marker = []byte("\r\n0;chunk-signature=")
						}
						idx := bytes.LastIndex(wire, marker)
						if idx < 0 {
							t.Fatal("final chunk not found")
						}
						body = wire[:idx+offset]
					case "bad final signature":
						marker := "x-amz-trailer-signature:"
						if !hasTrailer {
							marker = "0;chunk-signature="
						}
						idx := bytes.LastIndex(wire, []byte(marker))
						if idx < 0 {
							t.Fatalf("SDK did not produce %q", marker)
						}
						body = bytes.Clone(wire)
						body[idx+len(marker)] ^= 1
					}
					req.ContentLength = int64(len(wire))
					req.Body = io.NopCloser(bytes.NewReader(body))
					rec := httptest.NewRecorder()
					router.ServeHTTP(rec, req)
					if tt.want == ErrNone {
						if rec.Code != http.StatusOK {
							t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
						}
						reader, err := obj.GetObjectNInfo(context.Background(), bucket, prefix+"/entry", nil, nil, ObjectOptions{})
						if err != nil {
							t.Fatal(err)
						}
						defer reader.Close()
						if got, err := io.ReadAll(reader); err != nil || !bytes.Equal(got, content) {
							t.Errorf("extracted content differs: err=%v", err)
						}
						return
					}
					var response APIErrorResponse
					_ = xml.Unmarshal(rec.Body.Bytes(), &response)
					want := errorCodes.ToAPIErr(tt.want)
					if rec.Code != want.HTTPStatusCode || response.Code != want.Code {
						t.Errorf("status/code = %d/%s, want %d/%s", rec.Code, response.Code, want.HTTPStatusCode, want.Code)
					}
					// Extract is not transactional: already extracted entries can
					// remain after a terminal integrity error.
				})
			}
		}
	}
}

// Copyright (c) 2026 Granary contributors
//
// This file is part of Granary, an unofficial fork derived from MinIO.
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/minio/minio-go/v7/pkg/signer"
	"github.com/relvo-labs/granary/internal/auth"
	hashreader "github.com/relvo-labs/granary/internal/hash"
	xhttp "github.com/relvo-labs/granary/internal/http"
)

type unsignedChunkedReadCounter struct {
	io.Reader
	reads int
}

func (r *unsignedChunkedReadCounter) Read(p []byte) (int, error) {
	r.reads++
	return r.Reader.Read(p)
}

// trailerErrorReader repeats err until stopped, allowing a failing test to
// terminate a reader that incorrectly retries errors. Throttle retries so a
// buggy reader cannot consume unbounded memory before the test deadline.
type trailerErrorReader struct {
	err   error
	stop  <-chan struct{}
	reads int
}

func (r *trailerErrorReader) Read([]byte) (int, error) {
	select {
	case <-r.stop:
		return 0, io.EOF
	case <-time.After(time.Millisecond):
		r.reads++
		return 0, r.err
	}
}

func TestChunkedReaderTrailerReadErrors(t *testing.T) {
	const value = "x-amz-checksum-crc32:NSRBwg=="
	const signature = value + "\r\nx-amz-trailer-signature:signature"
	readErr := errors.New("trailer read failed")
	for _, tt := range []struct {
		name   string
		prefix string
		signed bool
	}{
		{name: "unsigned value"},
		{name: "unsigned partial value", prefix: value},
		{name: "unsigned terminator", prefix: value + "\r"},
		{name: "unsigned partial terminator LF", prefix: value + "\r\n"},
		{name: "unsigned partial terminator CR", prefix: value + "\r\n\r"},
		{name: "signed value", signed: true},
		{name: "signed partial value", prefix: value, signed: true},
		{name: "signed value LF", prefix: value + "\r", signed: true},
		{name: "signed signature", prefix: value + "\r\n", signed: true},
		{name: "signed partial signature", prefix: signature, signed: true},
		{name: "signed terminator", prefix: signature + "\r", signed: true},
		{name: "signed partial terminator LF", prefix: signature + "\r\n", signed: true},
		{name: "signed partial terminator CR", prefix: signature + "\r\n\r", signed: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, want := range []error{readErr, io.ErrUnexpectedEOF, io.EOF} {
				t.Run(want.Error(), func(t *testing.T) {
					stop := make(chan struct{})
					done := make(chan struct{})
					result := make(chan error, 1)
					body := &trailerErrorReader{err: want, stop: stop}
					reader := bufio.NewReader(io.MultiReader(strings.NewReader(tt.prefix), body))
					t.Cleanup(func() {
						close(stop)
						<-done
					})
					go func() {
						defer close(done)
						if tt.signed {
							result <- (&s3ChunkedReader{reader: reader}).readTrailers()
						} else {
							result <- (&s3UnsignedChunkedReader{reader: reader}).readTrailers()
						}
					}()
					deadline := time.NewTimer(time.Second)
					defer deadline.Stop()
					select {
					case got := <-result:
						<-done
						if errors.Is(want, io.EOF) || errors.Is(want, io.ErrUnexpectedEOF) {
							want = IncompleteBody{}
						}
						if got != want {
							t.Errorf("readTrailers error = %v, want %v", got, want)
						}
						if body.reads != 1 {
							t.Errorf("readTrailers retried a read error: reads = %d, want 1", body.reads)
						}
					case <-deadline.C:
						t.Fatal("readTrailers did not return before the deadline")
					}
				})
			}
		})
	}
}

func TestUnsignedChunkedReaderTerminal(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		trailer    bool
		want       error
	}{
		{name: "EOF", body: "3\r\nabc\r\n0\r\n\r\n", want: io.EOF},
		{name: "trailer EOF", body: "3\r\nabc\r\n0\r\nx-amz-checksum-crc32:NSRBwg==\r\n\r\n", trailer: true, want: io.EOF},
		{name: "truncated chunk", body: "3\r\nab", want: IncompleteBody{}},
		{name: "malformed chunk", body: "z\r\n", want: errMalformedEncoding},
		{name: "oversized chunk", body: "1000001\r\n", want: errChunkTooBig},
		{name: "truncated trailer", body: "0\r\nx-amz-checksum-crc32:", trailer: true, want: IncompleteBody{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := &unsignedChunkedReadCounter{Reader: strings.NewReader(tt.body)}
			cr := &s3UnsignedChunkedReader{reader: bufio.NewReader(body)}
			if tt.trailer {
				cr.trailers = http.Header{"X-Amz-Checksum-Crc32": {""}}
			}
			var buf [16]byte
			var data strings.Builder
			for {
				n, err := cr.Read(buf[:])
				data.Write(buf[:n])
				if err == nil {
					continue
				}
				if err != tt.want {
					t.Fatalf("terminal error = %v, want %v", err, tt.want)
				}
				break
			}
			if tt.want == io.EOF {
				if data.String() != "abc" {
					t.Errorf("decoded payload = %q, want abc", data.String())
				}
				if tt.trailer && cr.trailers.Get("X-Amz-Checksum-Crc32") != "NSRBwg==" {
					t.Errorf("trailer was not populated: %v", cr.trailers)
				}
			}
			reads := body.reads
			for range 3 {
				if n, err := cr.Read(buf[:]); n != 0 || err != tt.want {
					t.Errorf("Read after terminal error = %d, %v, want 0, %v", n, err, tt.want)
				}
				if body.reads != reads {
					t.Errorf("Read touched underlying body: reads = %d, want %d", body.reads, reads)
				}
			}
		})
	}
}

// The SDK requires a hash.Hash with Close for streaming SHA256 signatures.
type trailerSHA256Hasher struct{ hash.Hash }

func (trailerSHA256Hasher) Close() {}

func TestStreamingTrailerTruncation(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testStreamingTrailerTruncation})
}

func testStreamingTrailerTruncation(obj ObjectLayer, instance, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
	payload := []byte("abc")
	for _, signed := range []bool{false, true} {
		for _, multipart := range []bool{false, true} {
			for _, tt := range []struct {
				name         string
				trim         int
				badChecksum  bool
				badSignature bool
				want         APIErrorCode
			}{
				{name: "complete"},
				{name: "bad checksum", badChecksum: true, want: ErrContentChecksumMismatch},
				{name: "bad signature", badSignature: true, want: ErrSignatureDoesNotMatch},
				{name: "missing final LF", trim: 1, badChecksum: true, want: ErrIncompleteBody},
				{name: "missing final CRLF", trim: 2, badChecksum: true, want: ErrIncompleteBody},
				{name: "missing terminator suffix", trim: 3, badChecksum: true, want: ErrIncompleteBody},
				{name: "missing terminator", trim: 4, badChecksum: true, want: ErrIncompleteBody},
				{name: "truncated bad signature", trim: 1, badSignature: true, want: ErrIncompleteBody},
			} {
				if tt.badSignature && !signed {
					continue
				}
				t.Run(fmt.Sprintf("%s/signed=%t/multipart=%t/%s", instance, signed, multipart, tt.name), func(t *testing.T) {
					object := fmt.Sprintf("trailer-%t-%t-%s", signed, multipart, strings.ReplaceAll(tt.name, " ", "-"))
					resource := "http://localhost/" + bucket + "/" + object
					var uploadID string
					if multipart {
						mi, err := obj.NewMultipartUpload(context.Background(), bucket, object, ObjectOptions{})
						if err != nil {
							t.Fatal(err)
						}
						uploadID = mi.UploadID
						defer obj.AbortMultipartUpload(context.Background(), bucket, object, uploadID, ObjectOptions{})
						resource += "?" + url.Values{"uploadId": {uploadID}, "partNumber": {"1"}}.Encode()
					}
					checksum := unsignedTrailerCRC(payload)
					if tt.badChecksum {
						checksum = "AAAAAA=="
					}
					req, err := http.NewRequest(http.MethodPut, resource, bytes.NewReader(payload))
					if err != nil {
						t.Fatal(err)
					}
					trailer := http.Header{"X-Amz-Checksum-Crc32": {checksum}}
					if signed {
						req.Header.Set("Content-Encoding", "aws-chunked")
						req.Trailer = trailer
						req = signer.StreamingSignV4(req, cred.AccessKey, cred.SecretKey, "", globalSite.Region(), int64(len(payload)), UTCNow(), trailerSHA256Hasher{sha256.New()})
					} else {
						req.Header.Set(xhttp.AmzContentSha256, unsignedPayloadTrailer)
						req = signer.SignV4Trailer(*req, cred.AccessKey, cred.SecretKey, "", globalSite.Region(), trailer)
					}
					wire, err := io.ReadAll(req.Body)
					req.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					if tt.badSignature {
						idx := bytes.Index(wire, []byte("x-amz-trailer-signature:"))
						if idx < 0 {
							t.Fatal("SDK did not produce a trailer signature")
						}
						wire[idx+len("x-amz-trailer-signature:")] ^= 1
					}
					// Keep the declared wire and decoded lengths intact. Only the
					// framing is truncated, after the complete payload is delivered.
					req.ContentLength = int64(len(wire))
					req.Body = io.NopCloser(bytes.NewReader(wire[:len(wire)-tt.trim]))
					rec := httptest.NewRecorder()
					router.ServeHTTP(rec, req)
					if tt.want == ErrNone {
						if rec.Code != http.StatusOK {
							t.Errorf("complete upload status = %d, want 200", rec.Code)
						}
					} else {
						var response APIErrorResponse
						_ = xml.Unmarshal(rec.Body.Bytes(), &response)
						want := errorCodes.ToAPIErr(tt.want)
						if rec.Code != want.HTTPStatusCode || response.Code != want.Code {
							t.Errorf("upload status/code = %d/%s, want %d/%s", rec.Code, response.Code, want.HTTPStatusCode, want.Code)
						}
					}
					method := http.MethodHead
					resource = "http://localhost/" + bucket + "/" + object
					if multipart {
						method = http.MethodGet
						resource += "?" + url.Values{"uploadId": {uploadID}}.Encode()
					}
					probe, err := newTestSignedRequestV4(method, resource, 0, nil, cred.AccessKey, cred.SecretKey, nil)
					if err != nil {
						t.Fatal(err)
					}
					rec = httptest.NewRecorder()
					router.ServeHTTP(rec, probe)
					if multipart {
						var parts ListPartsResponse
						if err := xml.Unmarshal(rec.Body.Bytes(), &parts); err != nil || rec.Code != http.StatusOK {
							t.Fatalf("ListParts status = %d, XML error = %v", rec.Code, err)
						}
						want := 0
						if tt.want == ErrNone {
							want = 1
						}
						if len(parts.Parts) != want {
							t.Errorf("ListParts count = %d, want %d", len(parts.Parts), want)
						}
					} else {
						want := http.StatusNotFound
						if tt.want == ErrNone {
							want = http.StatusOK
						}
						if rec.Code != want {
							t.Errorf("HEAD status = %d, want %d", rec.Code, want)
						}
					}
				})
			}
		}
	}
}

// Construct valid frames for testing parser boundaries without request auth.
// Handler tests above independently use the SDK signer for interoperability.
func chunkedReaderTestStream(signed bool, trailer string) (string, func(*bufio.Reader) io.Reader) {
	headers := func() http.Header { return http.Header{"X-Amz-Checksum-Crc32": {""}} }
	if !signed {
		return "3\r\nabc\r\n0\r\n" + trailer + "\r\n\r\n", func(r *bufio.Reader) io.Reader {
			return &s3UnsignedChunkedReader{reader: r, trailers: headers()}
		}
	}
	cr := &s3ChunkedReader{chunkSHA256Writer: sha256.New()}
	var wire strings.Builder
	for _, data := range []string{"abc", ""} {
		cr.chunkSHA256Writer.Write([]byte(data))
		sig := cr.getChunkSignature()
		fmt.Fprintf(&wire, "%x;chunk-signature=%s\r\n%s", len(data), sig, data)
		if data != "" {
			wire.WriteString("\r\n")
		}
		cr.seedSignature = sig
		cr.chunkSHA256Writer.Reset()
	}
	if trailer != "" {
		cr.chunkSHA256Writer.Write([]byte(trailer + "\n"))
	}
	fmt.Fprintf(&wire, "%s\r\nx-amz-trailer-signature:%s\r\n\r\n", trailer, cr.getTrailerChunkSignature())
	return wire.String(), func(r *bufio.Reader) io.Reader {
		return &s3ChunkedReader{reader: r, trailers: headers(), chunkSHA256Writer: sha256.New()}
	}
}

func TestChunkedReaderTruncation(t *testing.T) {
	for _, signed := range []bool{false, true} {
		wire, newReader := chunkedReaderTestStream(signed, "x-amz-checksum-crc32:"+unsignedTrailerCRC([]byte("abc")))
		for cut := 0; cut < len(wire); cut++ {
			for _, withHash := range []bool{false, true} {
				t.Run(fmt.Sprintf("signed=%t/cut=%d/hash=%t", signed, cut, withHash), func(t *testing.T) {
					body := &unsignedChunkedReadCounter{Reader: strings.NewReader(wire[:cut])}
					cr := newReader(bufio.NewReader(body))
					r := cr
					if withHash {
						var err error
						r, err = hashreader.NewReader(context.Background(), cr, 3, "", "", 3)
						if err != nil {
							t.Fatal(err)
						}
					}
					_, err := io.ReadAll(r)
					if err != (IncompleteBody{}) {
						t.Errorf("truncation error = %v, want IncompleteBody", err)
					}
					// Extract can wrap errors from tar.Reader before mapping them.
					apiErr := toAPIError(context.Background(), fmt.Errorf("tar file error: %w", err))
					if apiErr.Code != "IncompleteBody" || apiErr.HTTPStatusCode != http.StatusBadRequest {
						t.Errorf("wrapped truncation status/code = %d/%s, want 400/IncompleteBody", apiErr.HTTPStatusCode, apiErr.Code)
					}
					reads := body.reads
					var buf [16]byte
					for range 3 {
						if n, next := cr.Read(buf[:]); n != 0 || next != err || body.reads != reads {
							t.Errorf("terminal Read = %d, %v, reads = %d; want 0, %v, %d", n, next, body.reads, err, reads)
						}
					}
				})
			}
		}
		// A complete frame which omits a declared trailer is also incomplete.
		wire, newReader = chunkedReaderTestStream(signed, "")
		if _, err := io.ReadAll(newReader(bufio.NewReader(strings.NewReader(wire)))); err != (IncompleteBody{}) {
			t.Errorf("signed=%t missing declared trailer error = %v, want IncompleteBody", signed, err)
		}
	}
}

func TestChunkedReaderDelimiterReadErrors(t *testing.T) {
	readErr := errors.New("delimiter read failed")
	for _, signed := range []bool{false, true} {
		wire, newReader := chunkedReaderTestStream(signed, "x-amz-checksum-crc32:"+unsignedTrailerCRC([]byte("abc")))
		payloadStart := strings.Index(wire, "\r\n") + 2
		for _, cut := range []int{payloadStart - 1, payloadStart + 3, payloadStart + 4} {
			for _, sourceErr := range []error{readErr, io.EOF, io.ErrUnexpectedEOF, fmt.Errorf("wrapped: %w", io.EOF), fmt.Errorf("wrapped: %w", io.ErrUnexpectedEOF)} {
				t.Run(fmt.Sprintf("signed=%t/cut=%d/%s", signed, cut, sourceErr), func(t *testing.T) {
					body := &unsignedChunkedReadCounter{Reader: io.MultiReader(strings.NewReader(wire[:cut]), iotest.ErrReader(sourceErr))}
					cr := newReader(bufio.NewReader(body))
					_, got := io.ReadAll(cr)
					want := sourceErr
					if errors.Is(sourceErr, io.EOF) || errors.Is(sourceErr, io.ErrUnexpectedEOF) {
						want = IncompleteBody{}
					}
					if got != want {
						t.Errorf("delimiter error = %v, want %v", got, want)
					}
					reads := body.reads
					var buf [16]byte
					if n, next := cr.Read(buf[:]); n != 0 || next != got || body.reads != reads {
						t.Errorf("terminal Read = %d, %v, reads = %d; want 0, %v, %d", n, next, body.reads, got, reads)
					}
				})
			}
		}
	}
}

func TestStreamingTrailerExtractTruncation(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testStreamingTrailerExtractTruncation})
}

func testStreamingTrailerExtractTruncation(_ ObjectLayer, instance, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
	for _, signed := range []bool{false, true} {
		t.Run(fmt.Sprintf("%s/signed=%t", instance, signed), func(t *testing.T) {
			// Keep the archive larger than untar's buffer to exercise read-ahead
			// and the unsigned reader's final drain after tar.Reader sees EOF.
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
			req, err := http.NewRequest(http.MethodPut, "http://localhost/"+bucket+"/extract-truncation", bytes.NewReader(archive.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(xhttp.AmzSnowballExtract, "true")
			req.Header.Set(xhttp.MinIOSnowballPrefix, "extract-truncation")
			trailer := http.Header{"X-Amz-Checksum-Crc32": {unsignedTrailerCRC(archive.Bytes())}}
			if signed {
				req.Header.Set("Content-Encoding", "aws-chunked")
				req.Trailer = trailer
				req = signer.StreamingSignV4(req, cred.AccessKey, cred.SecretKey, "", globalSite.Region(), int64(archive.Len()), UTCNow(), trailerSHA256Hasher{sha256.New()})
			} else {
				req.Header.Set(xhttp.AmzContentSha256, unsignedPayloadTrailer)
				req = signer.SignV4Trailer(*req, cred.AccessKey, cred.SecretKey, "", globalSite.Region(), trailer)
			}
			wire, err := io.ReadAll(req.Body)
			req.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			req.ContentLength = int64(len(wire))
			req.Body = io.NopCloser(bytes.NewReader(wire[:len(wire)-1]))
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			var response APIErrorResponse
			_ = xml.Unmarshal(rec.Body.Bytes(), &response)
			if rec.Code != http.StatusBadRequest || response.Code != "IncompleteBody" {
				t.Errorf("Extract status/code = %d/%s, want 400/IncompleteBody", rec.Code, response.Code)
			}
			// Extract is not transactional: already extracted entries can remain.
		})
	}
}

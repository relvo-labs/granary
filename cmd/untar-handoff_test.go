// Copyright (c) 2026 Granary contributors
//
// This file is part of Granary, an unofficial fork derived from MinIO.
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7/pkg/signer"
	"github.com/relvo-labs/granary/internal/auth"
	xhttp "github.com/relvo-labs/granary/internal/http"
)

const (
	// bzip2 -9 of a USTAR archive holding one entry, "entry", with
	// bzip2HandoffContent.
	bzip2HandoffArchive = "QlpoOTFBWSZTWcJ0ZfQAAHVbgMoUQAB3gAAId+HeMAgIIAB1EU9TxQA9T0gBk09QSUjIaGgAAGkfaCRCCZqEIf06cZYxyBDFpIPhByTZrJQGMAYCQowZFvuGs7RMgXr2KjtCTo/YSlMp4Uu+XzEcUkH4u5IpwoSGE6MvoA=="
	// bzip2 -9 of 512 zero bytes; its block magic ends the scanner's first
	// block.
	bzip2HandoffZeros   = "QlpoOTFBWSZTWR6uVU0AAAHAAMAAAAggADCASeoGri7kinChID1cqpo="
	bzip2HandoffContent = "granary bzip2 handoff\n"
	// The source is held when it reaches the 15th 64 KiB chunk boundary.
	bzip2HandoffHoldAt = 15 << 16
)

// bzip2HandoffPayload returns a bzip2 upload whose tar archive ends in the
// first block while the pbzip2 scanner still needs input. pbzip2 only emits
// a block once ~930 KB of lookahead is buffered; the gap pushes the next
// block magic far enough that the second lookahead extends past
// bzip2HandoffHoldAt. A source held there therefore keeps a scanner Read in
// flight after tar.Reader has already seen the archive terminator.
func bzip2HandoffPayload(t *testing.T) []byte {
	t.Helper()
	archive, err := base64.StdEncoding.DecodeString(bzip2HandoffArchive)
	if err != nil {
		t.Fatal(err)
	}
	zeros, err := base64.StdEncoding.DecodeString(bzip2HandoffZeros)
	if err != nil {
		t.Fatal(err)
	}
	payload := append(archive, make([]byte, 70000)...)
	payload = append(payload, zeros...)
	return append(payload, make([]byte, bzip2HandoffHoldAt+2<<16-len(payload))...)
}

// handoffReader serves data, holding the first Read that starts at holdAt
// until release is closed or holdFor elapses. It records overlapping Reads
// and Reads that start after the decompressor's owner gave the reader back.
type handoffReader struct {
	mu         sync.Mutex
	data       []byte
	off        int
	holdAt     int
	holdFor    time.Duration
	held       chan struct{} // closed when the hold starts
	release    chan struct{} // closed by the test to end the hold
	released   chan struct{} // closed when the hold ends
	holding    bool
	isReleased bool

	inFlight atomic.Int32
	overlap  atomic.Bool
	handed   atomic.Bool
	stray    atomic.Bool
}

func newHandoffReader(data []byte, holdAt int) *handoffReader {
	return &handoffReader{
		data: data, holdAt: holdAt,
		held: make(chan struct{}), release: make(chan struct{}), released: make(chan struct{}),
	}
}

// Read is the decompressor side of the source.
func (h *handoffReader) Read(p []byte) (int, error) {
	if h.handed.Load() {
		h.stray.Store(true)
	}
	return h.read(p)
}

func (h *handoffReader) read(p []byte) (int, error) {
	if h.inFlight.Add(1) > 1 {
		h.overlap.Store(true)
	}
	defer h.inFlight.Add(-1)
	h.mu.Lock()
	defer h.mu.Unlock()
	for h.off == h.holdAt && !h.isReleased {
		if h.holding {
			// Another Read while held waits for the same release.
			h.mu.Unlock()
			<-h.released
			h.mu.Lock()
			continue
		}
		h.holding = true
		close(h.held)
		h.mu.Unlock()
		if h.holdFor > 0 {
			time.Sleep(h.holdFor)
		} else {
			<-h.release
		}
		h.mu.Lock()
		h.isReleased = true
		close(h.released)
	}
	if h.off >= len(h.data) {
		return 0, io.EOF
	}
	end := len(h.data)
	if h.off < h.holdAt {
		end = min(end, h.holdAt)
	}
	n := copy(p, h.data[h.off:end])
	h.off += n
	return n, nil
}

type handoffDrain struct{ h *handoffReader }

func (d handoffDrain) Read(p []byte) (int, error) { return d.h.read(p) }

// untar must not return while a decompressor goroutine is still reading its
// source: the Extract handler drains the same reader right afterwards to
// verify the streaming terminal.
func TestUntarStopsDecompressorReadsBeforeReturn(t *testing.T) {
	src := newHandoffReader(bzip2HandoffPayload(t), bzip2HandoffHoldAt)
	var (
		mu      sync.Mutex
		entries = map[string]string{}
	)
	putObject := func(r io.Reader, _ os.FileInfo, name string) error {
		b, err := io.ReadAll(r)
		mu.Lock()
		entries[name] = string(b)
		mu.Unlock()
		return err
	}
	done := make(chan error, 1)
	go func() { done <- untar(t.Context(), src, putObject, untarOptions{}) }()

	select {
	case <-src.held:
	case err := <-done:
		close(src.release)
		t.Fatalf("untar returned %v before the bzip2 scanner reached the hold point", err)
	case <-time.After(time.Minute):
		close(src.release)
		t.Fatal("bzip2 scanner did not reach the hold point")
	}
	// The archive terminator is decoded while the scanner's next Read is
	// held. Returning now would hand a reader with an in-flight Read to the
	// caller.
	var err error
	returned := false
	select {
	case err = <-done:
		returned = true
		t.Errorf("untar returned while a decompressor Read of its source was in flight (in-flight=%d)", src.inFlight.Load())
	case <-time.After(time.Second):
	}
	close(src.release)
	if !returned {
		select {
		case err = <-done:
		case <-time.After(time.Minute):
			t.Fatal("untar did not return after the source was released")
		}
	}
	if err != nil {
		t.Fatalf("untar: %v", err)
	}
	src.handed.Store(true)
	// Drain the rest as the Extract handler does.
	if _, err := io.Copy(io.Discard, handoffDrain{src}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if src.overlap.Load() {
		t.Error("caller drain overlapped a decompressor Read")
	}
	if src.stray.Load() {
		t.Error("decompressor read its source after untar returned")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(entries) != 1 || entries["entry"] != bzip2HandoffContent {
		t.Errorf("extracted entries = %q", entries)
	}
}

// End to end: the Extract handler's terminal drain must not race with bzip2
// read-ahead, and must still report the terminal verification result.
func TestStreamingExtractBzip2ReadAheadHandoff(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: testStreamingExtractBzip2ReadAheadHandoff})
}

func testStreamingExtractBzip2ReadAheadHandoff(obj ObjectLayer, instance, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
	payload := bzip2HandoffPayload(t)
	for _, mode := range []string{"unsigned-trailer", "signed-trailer", "signed"} {
		for _, corrupt := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%s/corrupt=%v", instance, mode, corrupt), func(t *testing.T) {
				prefix := fmt.Sprintf("extract-bz2-handoff-%s-%v", mode, corrupt)
				req, err := http.NewRequest(http.MethodPut, "http://localhost/"+bucket+"/"+prefix+".tar.bz2", bytes.NewReader(payload))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set(xhttp.AmzSnowballExtract, "true")
				req.Header.Set(xhttp.MinIOSnowballPrefix, prefix)
				trailer := http.Header{"X-Amz-Checksum-Crc32": {unsignedTrailerCRC(payload)}}
				want := ErrNone
				if mode == "unsigned-trailer" {
					if corrupt {
						trailer.Set("X-Amz-Checksum-Crc32", "AAAAAA==")
						want = ErrContentChecksumMismatch
					}
					req.Header.Set(xhttp.AmzContentSha256, unsignedPayloadTrailer)
					req = signer.SignV4Trailer(*req, cred.AccessKey, cred.SecretKey, "", globalSite.Region(), trailer)
				} else {
					req.Header.Set("Content-Encoding", "aws-chunked")
					if mode == "signed-trailer" {
						req.Trailer = trailer
					}
					req = signer.StreamingSignV4(req, cred.AccessKey, cred.SecretKey, "", globalSite.Region(), int64(len(payload)), UTCNow(), trailerSHA256Hasher{sha256.New()})
				}
				wire, err := io.ReadAll(req.Body)
				req.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if corrupt && mode != "unsigned-trailer" {
					marker := "x-amz-trailer-signature:"
					if mode == "signed" {
						marker = "0;chunk-signature="
					}
					idx := bytes.LastIndex(wire, []byte(marker))
					if idx < 0 {
						t.Fatalf("SDK did not produce %q", marker)
					}
					wire[idx+len(marker)] ^= 1
					want = ErrSignatureDoesNotMatch
				}
				body := newHandoffReader(wire, wireOffsetOfPayload(t, wire, bzip2HandoffHoldAt))
				// Delay the rest of the upload while bzip2 reads ahead.
				body.holdFor = 300 * time.Millisecond
				req.ContentLength = int64(len(wire))
				req.Body = io.NopCloser(handoffDrain{body})
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				select {
				case <-body.held:
				default:
					t.Fatal("upload was not held during bzip2 read-ahead")
				}
				if body.overlap.Load() {
					t.Error("terminal drain overlapped a bzip2 read-ahead Read of the request body")
				}
				if want == ErrNone {
					if rec.Code != http.StatusOK {
						t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
					}
					reader, err := obj.GetObjectNInfo(context.Background(), bucket, prefix+"/entry", nil, nil, ObjectOptions{})
					if err != nil {
						t.Fatal(err)
					}
					defer reader.Close()
					if got, err := io.ReadAll(reader); err != nil || string(got) != bzip2HandoffContent {
						t.Errorf("extracted content = %q, err=%v", got, err)
					}
					return
				}
				var response APIErrorResponse
				_ = xml.Unmarshal(rec.Body.Bytes(), &response)
				apiErr := errorCodes.ToAPIErr(want)
				if rec.Code != apiErr.HTTPStatusCode || response.Code != apiErr.Code {
					t.Errorf("status/code = %d/%s, want %d/%s", rec.Code, response.Code, apiErr.HTTPStatusCode, apiErr.Code)
				}
			})
		}
	}
}

// wireOffsetOfPayload returns the aws-chunked wire offset of the chunk header
// that starts at decoded payload offset off.
func wireOffsetOfPayload(t *testing.T, wire []byte, off int) int {
	t.Helper()
	pos, decoded := 0, 0
	for decoded < off {
		eol := bytes.Index(wire[pos:], []byte("\r\n"))
		if eol < 0 {
			t.Fatalf("no chunk header at wire offset %d", pos)
		}
		size, _, _ := bytes.Cut(wire[pos:pos+eol], []byte(";"))
		n, err := strconv.ParseInt(string(size), 16, 64)
		if err != nil || n == 0 {
			t.Fatalf("chunk header %q at wire offset %d: %v", wire[pos:pos+eol], pos, err)
		}
		pos += eol + 2 + int(n) + 2
		decoded += int(n)
	}
	if decoded != off {
		t.Fatalf("payload offset %d is not a chunk boundary", off)
	}
	return pos
}

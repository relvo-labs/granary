// Copyright (c) 2026 Granary contributors
//
// This file is part of Granary, an unofficial fork derived from MinIO.
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
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
						if want == io.EOF {
							want = io.ErrUnexpectedEOF
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
		{name: "truncated chunk", body: "3\r\nab", want: io.ErrUnexpectedEOF},
		{name: "malformed chunk", body: "z\r\n", want: errMalformedEncoding},
		{name: "oversized chunk", body: "1000001\r\n", want: errChunkTooBig},
		{name: "truncated trailer", body: "0\r\nx-amz-checksum-crc32:", trailer: true, want: io.ErrUnexpectedEOF},
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

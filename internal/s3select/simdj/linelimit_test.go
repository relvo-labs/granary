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

package simdj

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

// TestLineLimitReader exercises the input wrapper independently of the
// host CPU, so the bound is covered where simdjson tests are skipped.
func TestLineLimitReader(t *testing.T) {
	if maxLineSize != testMaxLineSize {
		t.Fatalf("maxLineSize = %d, want %d", maxLineSize, testMaxLineSize)
	}
	const limit = 16
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty", "", false},
		{"limit-newline", strings.Repeat("y", limit) + "\n" + "next\n", false},
		{"limit+1-newline", strings.Repeat("y", limit+1) + "\n" + "next\n", true},
		{"limit-eof", "a\n" + strings.Repeat("y", limit), false},
		{"limit+1-eof", "a\n" + strings.Repeat("y", limit+1), true},
		{"many-limit-lines", strings.Repeat(strings.Repeat("y", limit)+"\n", 10), false},
		{"empty-lines", "\n\n\n", false},
		{"crlf-counts-cr", strings.Repeat("y", limit) + "\r\n", true},
	}
	for _, c := range cases {
		for _, oneByte := range []bool{false, true} {
			name := c.name
			if oneByte {
				name += "/onebyte"
			}
			t.Run(name, func(t *testing.T) {
				var src io.Reader = strings.NewReader(c.input)
				if oneByte {
					src = iotest.OneByteReader(src)
				}
				got, err := io.ReadAll(newLineLimitReader(src, limit))
				if c.wantErr {
					if code := errorCode(err); code != overMaxRecordSizeCode {
						t.Fatalf("want %s error, got %v (code %q)", overMaxRecordSizeCode, err, code)
					}
					if i := bytes.LastIndexByte(got, '\n'); len(got)-(i+1) > limit {
						t.Fatalf("returned a %d-byte partial line", len(got)-(i+1))
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if string(got) != c.input {
					t.Fatalf("data mismatch: got %d bytes, want %d", len(got), len(c.input))
				}
			})
		}
	}
}

// TestLineLimitReaderNoNewlineBounded checks that the wrapper stops pulling
// input after the limit plus one read, and that the error is sticky.
func TestLineLimitReaderNoNewlineBounded(t *testing.T) {
	src := &countingByteReader{b: 'a', limit: 64 << 20}
	lr := newLineLimitReader(src, testMaxLineSize)
	buf := make([]byte, 32<<10)
	var total int
	var err error
	for err == nil {
		var n int
		n, err = lr.Read(buf)
		total += n
	}
	if code := errorCode(err); code != overMaxRecordSizeCode {
		t.Fatalf("want %s error, got %v (code %q)", overMaxRecordSizeCode, err, code)
	}
	if total > testMaxLineSize {
		t.Fatalf("returned %d bytes of a single line", total)
	}
	if src.n > int64(testMaxLineSize+len(buf)) {
		t.Fatalf("consumed %d bytes of input", src.n)
	}
	consumed := src.n
	if n, err2 := lr.Read(buf); n != 0 || errorCode(err2) != overMaxRecordSizeCode || src.n != consumed {
		t.Fatalf("error not sticky: n=%d err=%v consumed=%d->%d", n, err2, consumed, src.n)
	}
}

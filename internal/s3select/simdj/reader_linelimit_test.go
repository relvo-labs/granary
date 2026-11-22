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
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/minio/simdjson-go"
	"github.com/relvo-labs/granary/internal/s3select/json"
	"github.com/relvo-labs/granary/internal/s3select/sql"
)

// testMaxLineSize pins the documented per-line input limit (S3 Select
// maxCharsPerRecord, 1 MiB). It intentionally does not reference the
// production constant so that the contract cannot silently drift.
const testMaxLineSize = 1 << 20

const overMaxRecordSizeCode = "OverMaxRecordSize"

// countingByteReader yields `limit` copies of b without any newline and
// records how many bytes were handed out.
type countingByteReader struct {
	b     byte
	n     int64
	limit int64
}

func (c *countingByteReader) Read(p []byte) (int, error) {
	if c.n >= c.limit {
		return 0, io.EOF
	}
	if rem := c.limit - c.n; int64(len(p)) > rem {
		p = p[:rem]
	}
	for i := range p {
		p[i] = c.b
	}
	c.n += int64(len(p))
	return len(p), nil
}

func errorCode(err error) string {
	var se interface{ ErrorCode() string }
	if errors.As(err, &se) {
		return se.ErrorCode()
	}
	return ""
}

// jsonLine returns a JSON object line of exactly n bytes, excluding newline.
func jsonLine(n int) string {
	const head, tail = `{"k":"`, `"}`
	return head + strings.Repeat("y", n-len(head)-len(tail)) + tail
}

func requireSIMD(t *testing.T) {
	t.Helper()
	if !simdjson.SupportedCPU() {
		t.Skip("simdjson not supported on this CPU; the PReader path covers this case")
	}
}

func readAll(t *testing.T, r *Reader) ([]string, error) {
	t.Helper()
	var out []string
	var rec sql.Record
	var err error
	for {
		rec, err = r.Read(rec)
		if err != nil {
			return out, err
		}
		v, verr := rec.(*Record).Get("k")
		if verr != nil {
			return out, verr
		}
		s, _ := v.ToString()
		out = append(out, s)
	}
}

func linesArgs() *json.ReaderArgs {
	return &json.ReaderArgs{ContentType: "lines"}
}

// TestReaderNoNewlineBounded reproduces issue #79 on the simdjson path:
// simdjson.ParseNDStream reads a 10 MiB block and then calls
// bufio.Reader.ReadBytes('\n') without a bound, so newline-free input was
// read until EOF. The reader must fail with OverMaxRecordSize after a
// bounded amount of input.
func TestReaderNoNewlineBounded(t *testing.T) {
	requireSIMD(t)
	src := &countingByteReader{b: 'a', limit: 64 << 20}
	r := NewReader(io.NopCloser(src), linesArgs())
	_, err := readAll(t, r)
	r.Close()
	if code := errorCode(err); code != overMaxRecordSizeCode {
		t.Fatalf("want %s error, got %v (code %q)", overMaxRecordSizeCode, err, code)
	}
	// ParseNDStream's own 10 MiB block read plus the line limit.
	const maxRead = 10<<20 + testMaxLineSize + 1<<20
	if src.n > maxRead {
		t.Fatalf("consumed %d bytes of input, want <= %d", src.n, int64(maxRead))
	}
}

// TestReaderLineLimitBoundary checks limit and limit+1 for a line in the
// middle of a stream and for the last line without a trailing newline.
func TestReaderLineLimitBoundary(t *testing.T) {
	requireSIMD(t)
	cases := []struct {
		name    string
		input   string
		wantErr bool
		want    int
	}{
		{"limit-newline", `{"k":"a"}` + "\n" + jsonLine(testMaxLineSize) + "\n" + `{"k":"b"}` + "\n", false, 3},
		{"limit+1-newline", `{"k":"a"}` + "\n" + jsonLine(testMaxLineSize+1) + "\n" + `{"k":"b"}` + "\n", true, 0},
		{"limit-eof", `{"k":"a"}` + "\n" + jsonLine(testMaxLineSize), false, 2},
		{"limit+1-eof", `{"k":"a"}` + "\n" + jsonLine(testMaxLineSize+1), true, 0},
		{"limit-first", jsonLine(testMaxLineSize) + "\n", false, 1},
		{"limit+1-first", jsonLine(testMaxLineSize+1) + "\n", true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := NewReader(io.NopCloser(strings.NewReader(c.input)), linesArgs())
			defer r.Close()
			recs, err := readAll(t, r)
			if c.wantErr {
				if code := errorCode(err); code != overMaxRecordSizeCode {
					t.Fatalf("want %s error, got %v (code %q) after %d records", overMaxRecordSizeCode, err, code, len(recs))
				}
				for _, s := range recs {
					if len(s) > testMaxLineSize {
						t.Fatalf("record with %d-byte value returned despite limit", len(s))
					}
				}
				return
			}
			if err != io.EOF {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(recs) != c.want {
				t.Fatalf("want %d records, got %d", c.want, len(recs))
			}
		})
	}
}

// TestReaderValidInputUnchanged checks that ordinary JSON Lines keep
// working on the simdjson path.
func TestReaderValidInputUnchanged(t *testing.T) {
	requireSIMD(t)
	var sb strings.Builder
	const n = 200000 // > one 10 MiB ParseNDStream block in total
	for range n {
		sb.WriteString(`{"k":"` + strings.Repeat("v", 50) + `"}` + "\n")
	}
	r := NewReader(io.NopCloser(strings.NewReader(sb.String())), linesArgs())
	defer r.Close()
	recs, err := readAll(t, r)
	if err != io.EOF {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(recs) != n {
		t.Fatalf("want %d records, got %d", n, len(recs))
	}
}

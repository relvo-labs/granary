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

package json

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/relvo-labs/granary/internal/s3select/sql"
)

// testMaxLineSize pins the documented per-line input limit (S3 Select
// maxCharsPerRecord, 1 MiB). It intentionally does not reference the
// production constant so that the contract cannot silently drift.
const testMaxLineSize = 1 << 20

const overMaxRecordSizeCode = "OverMaxRecordSize"

// countingByteReader yields `limit` copies of b without any newline and
// records how many bytes were handed out, so tests can prove that the reader
// stops consuming input once the line limit is exceeded.
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

func newSplitTestPReader(r io.Reader) *PReader {
	return &PReader{buf: bufio.NewReaderSize(r, jsonSplitSize*2)}
}

// jsonLine returns a JSON object line of exactly n bytes, excluding newline.
func jsonLine(n int) string {
	const head, tail = `{"k":"`, `"}`
	return head + strings.Repeat("y", n-len(head)-len(tail)) + tail
}

// TestPReaderNextSplitLineLimitBoundary checks the exact boundary of the
// per-line limit, both for a line starting at the read position (skip == 0)
// and for a line that starts inside the skipped block.
func TestPReaderNextSplitLineLimitBoundary(t *testing.T) {
	const prefix = "{\"short\":1}\n"
	cases := []struct {
		name    string
		skip    int
		input   string
		wantErr bool
		wantLen int
	}{
		{"skip0-limit-newline", 0, strings.Repeat("y", testMaxLineSize) + "\nnext\n", false, testMaxLineSize + 1},
		{"skip0-limit+1-newline", 0, strings.Repeat("y", testMaxLineSize+1) + "\nnext\n", true, 0},
		{"skip0-limit-eof", 0, strings.Repeat("y", testMaxLineSize), false, testMaxLineSize},
		{"skip0-limit+1-eof", 0, strings.Repeat("y", testMaxLineSize+1), true, 0},
		{"block-straddle-limit", jsonSplitSize, prefix + strings.Repeat("y", testMaxLineSize) + "\nnext\n", false, len(prefix) + testMaxLineSize + 1},
		{"block-straddle-limit+1", jsonSplitSize, prefix + strings.Repeat("y", testMaxLineSize+1) + "\nnext\n", true, 0},
		{"block-from-start-limit", jsonSplitSize, strings.Repeat("y", testMaxLineSize) + "\nnext\n", false, testMaxLineSize + 1},
		{"block-from-start-limit+1", jsonSplitSize, strings.Repeat("y", testMaxLineSize+1) + "\nnext\n", true, 0},
		{"block-ends-on-newline-limit", jsonSplitSize, strings.Repeat("y", jsonSplitSize-1) + "\n" + strings.Repeat("y", testMaxLineSize) + "\n", false, jsonSplitSize + testMaxLineSize + 1},
		{"block-ends-on-newline-limit+1", jsonSplitSize, strings.Repeat("y", jsonSplitSize-1) + "\n" + strings.Repeat("y", testMaxLineSize+1) + "\n", true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newSplitTestPReader(strings.NewReader(c.input))
			got, err := r.nextSplit(c.skip, nil)
			if c.wantErr {
				if code := errorCode(err); code != overMaxRecordSizeCode {
					t.Fatalf("want %s error, got err=%v (code %q), len=%d", overMaxRecordSizeCode, err, code, len(got))
				}
				if len(got) != 0 {
					t.Fatalf("over-limit split must not return partial data, got %d bytes", len(got))
				}
				return
			}
			if err != nil && err != io.EOF {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != c.wantLen {
				t.Fatalf("want %d bytes, got %d", c.wantLen, len(got))
			}
		})
	}
}

// TestPReaderNextSplitNoNewlineBounded feeds a large input without any
// newline and verifies the splitter errors out after consuming a bounded
// amount of input instead of buffering everything until EOF.
func TestPReaderNextSplitNoNewlineBounded(t *testing.T) {
	for _, skip := range []int{0, jsonSplitSize} {
		src := &countingByteReader{b: 'a', limit: 64 << 20}
		r := newSplitTestPReader(src)
		got, err := r.nextSplit(skip, nil)
		if code := errorCode(err); code != overMaxRecordSizeCode {
			t.Fatalf("skip=%d: want %s error, got err=%v (code %q)", skip, overMaxRecordSizeCode, err, code)
		}
		// skip + line limit + at most one bufio buffer of read-ahead.
		maxRead := int64(skip + testMaxLineSize + 2*jsonSplitSize*2)
		if src.n > maxRead {
			t.Fatalf("skip=%d: consumed %d bytes of input, want <= %d", skip, src.n, maxRead)
		}
		if len(got) != 0 {
			t.Fatalf("skip=%d: over-limit split returned %d bytes", skip, len(got))
		}
	}
}

func readAllPReader(t *testing.T, r *PReader) ([]string, error) {
	t.Helper()
	var out []string
	var rec sql.Record
	var err error
	for {
		rec, err = r.Read(rec)
		if err != nil {
			return out, err
		}
		out = append(out, recordK(rec.(*Record)))
	}
}

// recordK returns the string value of key "k" of a decoded record.
// (*Record).Get is not implemented in this package; inspect KVS directly.
func recordK(rec *Record) string {
	for _, kv := range rec.KVS {
		if kv.Key == "k" {
			s, _ := kv.Value.(string)
			return s
		}
	}
	return ""
}

// TestPReaderNoNewlineBounded drives the whole parallel reader with a
// newline-free input and checks it fails with OverMaxRecordSize after a
// bounded amount of input.
func TestPReaderNoNewlineBounded(t *testing.T) {
	src := &countingByteReader{b: 'a', limit: 64 << 20}
	r := NewPReader(io.NopCloser(src), &ReaderArgs{ContentType: "lines", unmarshaled: true})
	_, err := readAllPReader(t, r)
	r.Close()
	if code := errorCode(err); code != overMaxRecordSizeCode {
		t.Fatalf("want %s error, got %v (code %q)", overMaxRecordSizeCode, err, code)
	}
	if max := int64(jsonSplitSize + testMaxLineSize + 4*jsonSplitSize*2); src.n > max {
		t.Fatalf("consumed %d bytes of input, want <= %d", src.n, max)
	}
}

// TestPReaderLineTooLong checks that a single over-limit line in an
// otherwise valid JSON Lines stream is rejected with OverMaxRecordSize.
func TestPReaderLineTooLong(t *testing.T) {
	var sb strings.Builder
	for range 20000 {
		sb.WriteString(`{"k":"a"}` + "\n")
	}
	sb.WriteString(jsonLine(testMaxLineSize+1) + "\n")
	sb.WriteString(`{"k":"b"}` + "\n")
	r := NewPReader(io.NopCloser(strings.NewReader(sb.String())), &ReaderArgs{ContentType: "lines", unmarshaled: true})
	defer r.Close()
	recs, err := readAllPReader(t, r)
	if code := errorCode(err); code != overMaxRecordSizeCode {
		t.Fatalf("want %s error, got %v (code %q) after %d records", overMaxRecordSizeCode, err, code, len(recs))
	}
	for _, s := range recs {
		if len(s) > testMaxLineSize {
			t.Fatalf("record with %d-byte value returned despite limit", len(s))
		}
	}
}

// TestPReaderValidInputUnchanged covers JSON Lines inputs that must keep
// working, including a line that is exactly at the limit and objects that
// span lines.
func TestPReaderValidInputUnchanged(t *testing.T) {
	limit := jsonLine(testMaxLineSize)
	limitVal := limit[len(`{"k":"`) : len(limit)-len(`"}`)]
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"simple", "{\"k\":\"1\"}\n{\"k\":\"2\"}\n", []string{"1", "2"}},
		{"no-trailing-newline", "{\"k\":\"1\"}\n{\"k\":\"2\"}", []string{"1", "2"}},
		{"crlf", "{\"k\":\"1\"}\r\n{\"k\":\"2\"}\r\n", []string{"1", "2"}},
		{"multi-line-object", "{\"k\":\n\"1\"}\n{\"k\":\"2\"}\n", []string{"1", "2"}},
		{"limit-line", "{\"k\":\"a\"}\n" + limit + "\n{\"k\":\"b\"}\n", []string{"a", limitVal, "b"}},
		{"limit-line-eof", "{\"k\":\"a\"}\n" + limit, []string{"a", limitVal}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := NewPReader(io.NopCloser(strings.NewReader(c.input)), &ReaderArgs{ContentType: "lines", unmarshaled: true})
			defer r.Close()
			recs, err := readAllPReader(t, r)
			if err != io.EOF {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(recs) != len(c.want) {
				t.Fatalf("want %d records, got %d", len(c.want), len(recs))
			}
			for i := range recs {
				if recs[i] != c.want[i] {
					t.Fatalf("record %d mismatch: got %d bytes", i, len(recs[i]))
				}
			}
		})
	}
}

// TestReaderDocumentLongLineUnchanged guards that DOCUMENT mode keeps its
// existing 10 MiB document cap and is not subject to the per-line limit.
func TestReaderDocumentLongLineUnchanged(t *testing.T) {
	doc := jsonLine(2 * testMaxLineSize)
	r := NewReader(io.NopCloser(strings.NewReader(doc)), &ReaderArgs{ContentType: "document", unmarshaled: true})
	defer r.Close()
	rec, err := r.Read(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s := recordK(rec.(*Record)); len(s) != len(doc)-len(`{"k":""}`) {
		t.Fatalf("got %d-byte value", len(s))
	}
	if _, err := r.Read(rec); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}

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

package csv

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

func newSplitTestReader(r io.Reader) *Reader {
	return &Reader{buf: bufio.NewReaderSize(r, csvSplitSize*2)}
}

func testReaderArgs(header, recordDelimiter string) *ReaderArgs {
	return &ReaderArgs{
		FileHeaderInfo:       header,
		RecordDelimiter:      recordDelimiter,
		FieldDelimiter:       ",",
		QuoteCharacter:       defaultQuoteCharacter,
		QuoteEscapeCharacter: defaultQuoteEscapeCharacter,
		CommentCharacter:     defaultCommentCharacter,
		unmarshaled:          true,
	}
}

// TestNextSplitLineLimitBoundary checks the exact boundary of the per-line
// limit, both for a line starting at the read position (skip == 0, the header
// path) and for a line that starts inside the skipped block.
func TestNextSplitLineLimitBoundary(t *testing.T) {
	const prefix = "short,line\n"
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
		{"block-straddle-limit", csvSplitSize, prefix + strings.Repeat("y", testMaxLineSize) + "\nnext\n", false, len(prefix) + testMaxLineSize + 1},
		{"block-straddle-limit+1", csvSplitSize, prefix + strings.Repeat("y", testMaxLineSize+1) + "\nnext\n", true, 0},
		{"block-from-start-limit", csvSplitSize, strings.Repeat("y", testMaxLineSize) + "\nnext\n", false, testMaxLineSize + 1},
		{"block-from-start-limit+1", csvSplitSize, strings.Repeat("y", testMaxLineSize+1) + "\nnext\n", true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newSplitTestReader(strings.NewReader(c.input))
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

// TestNextSplitNoNewlineBounded feeds a large input without any newline and
// verifies the splitter errors out after consuming a bounded amount of input
// instead of buffering everything until EOF.
func TestNextSplitNoNewlineBounded(t *testing.T) {
	for _, skip := range []int{0, csvSplitSize} {
		src := &countingByteReader{b: 'a', limit: 64 << 20}
		r := newSplitTestReader(src)
		got, err := r.nextSplit(skip, nil)
		if code := errorCode(err); code != overMaxRecordSizeCode {
			t.Fatalf("skip=%d: want %s error, got err=%v (code %q)", skip, overMaxRecordSizeCode, err, code)
		}
		// skip + line limit + at most one bufio buffer of read-ahead.
		maxRead := int64(skip + testMaxLineSize + 2*csvSplitSize*2)
		if src.n > maxRead {
			t.Fatalf("skip=%d: consumed %d bytes of input, want <= %d", skip, src.n, maxRead)
		}
		if len(got) != 0 {
			t.Fatalf("skip=%d: over-limit split returned %d bytes", skip, len(got))
		}
	}
}

func TestReaderHeaderLineTooLong(t *testing.T) {
	src := &countingByteReader{b: 'h', limit: 64 << 20}
	r, err := NewReader(io.NopCloser(src), testReaderArgs(use, "\n"))
	if code := errorCode(err); code != overMaxRecordSizeCode {
		if r != nil {
			r.Close()
		}
		t.Fatalf("want %s error, got %v (code %q)", overMaxRecordSizeCode, err, code)
	}
	if src.n > int64(testMaxLineSize+4*csvSplitSize) {
		t.Fatalf("consumed %d bytes of input for the header", src.n)
	}
}

func readAll(t *testing.T, r *Reader) ([][]string, error) {
	t.Helper()
	var out [][]string
	var rec sql.Record
	var err error
	for {
		rec, err = r.Read(rec)
		if err != nil {
			return out, err
		}
		out = append(out, append([]string(nil), rec.(*Record).csvRecord...))
	}
}

func TestReaderBodyLineTooLong(t *testing.T) {
	for _, delim := range []string{"\n", "\r\n", ";"} {
		t.Run(strings.ReplaceAll(strings.ReplaceAll(delim, "\r", `\r`), "\n", `\n`), func(t *testing.T) {
			var sb strings.Builder
			for range 2000 {
				sb.WriteString("a,b" + delim)
			}
			sb.WriteString(strings.Repeat("y", testMaxLineSize+1) + delim)
			sb.WriteString("c,d" + delim)
			r, err := NewReader(io.NopCloser(strings.NewReader(sb.String())), testReaderArgs(none, delim))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			recs, err := readAll(t, r)
			if code := errorCode(err); code != overMaxRecordSizeCode {
				t.Fatalf("want %s error, got %v (code %q) after %d records", overMaxRecordSizeCode, err, code, len(recs))
			}
			for _, rec := range recs {
				for _, f := range rec {
					if len(f) > testMaxLineSize {
						t.Fatalf("record with %d-byte field returned despite limit", len(f))
					}
				}
			}
		})
	}
}

// TestReaderValidInputUnchanged covers inputs that must keep working:
// quoted fields containing newlines, alternative record delimiters and a
// line that is exactly at the limit.
func TestReaderValidInputUnchanged(t *testing.T) {
	long := strings.Repeat("y", testMaxLineSize-2)
	cases := []struct {
		name   string
		delim  string
		header string
		input  string
		want   [][]string
	}{
		{"quoted-newline", "\n", none, "x,\"multi\nline\"\nlast,row\n", [][]string{{"x", "multi\nline"}, {"last", "row"}}},
		{"crlf", "\r\n", none, "1,2\r\n3,4\r\n", [][]string{{"1", "2"}, {"3", "4"}}},
		{"tab-delim", "\t", none, "1,2\t3,4\t", [][]string{{"1", "2"}, {"3", "4"}}},
		{"limit-line-lf", "\n", none, "a,b\n" + long + ",z\nc,d\n", [][]string{{"a", "b"}, {long, "z"}, {"c", "d"}}},
		{"limit-line-crlf", "\r\n", none, "a,b\r\n" + long + ",z\r\nc,d\r\n", [][]string{{"a", "b"}, {long, "z"}, {"c", "d"}}},
		{"limit-header", "\n", use, long + ",z\n1,2\n", [][]string{{"1", "2"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := NewReader(io.NopCloser(strings.NewReader(c.input)), testReaderArgs(c.header, c.delim))
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			recs, err := readAll(t, r)
			if err != io.EOF {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(recs) != len(c.want) {
				t.Fatalf("want %d records, got %d", len(c.want), len(recs))
			}
			for i := range recs {
				if strings.Join(recs[i], "\x00") != strings.Join(c.want[i], "\x00") {
					t.Fatalf("record %d mismatch: got %q", i, recs[i])
				}
			}
			if c.header == use && (len(r.columnNames) != 2 || r.columnNames[0] != long) {
				t.Fatalf("header not parsed")
			}
		})
	}
}

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

package s3select

import (
	"bytes"
	"compress/gzip"
	"errors"
	"testing"
)

// TestCSVCompressedNoNewlineBounded reproduces CVE-2026-39414 /
// GHSA-h749-fxx7-pwpg: a small GZIP object that decompresses into a long
// run of bytes without any newline must fail with OverMaxRecordSize after a
// bounded amount of decompressed input, instead of being buffered whole.
func TestCSVCompressedNoNewlineBounded(t *testing.T) {
	const decompressed = 32 << 20 // kept small so the pre-fix behavior stays testable
	var obj bytes.Buffer
	zw, err := gzip.NewWriterLevel(&obj, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte{'a'}, 1<<20)
	for range decompressed / len(chunk) {
		if _, err := zw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	reqFor := func(header string) []byte {
		return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<SelectObjectContentRequest>
    <Expression>SELECT COUNT(*) FROM S3Object</Expression>
    <ExpressionType>SQL</ExpressionType>
    <InputSerialization>
        <CompressionType>GZIP</CompressionType>
        <CSV>
            <FileHeaderInfo>` + header + `</FileHeaderInfo>
        </CSV>
    </InputSerialization>
    <OutputSerialization>
        <CSV>
        </CSV>
    </OutputSerialization>
    <RequestProgress>
        <Enabled>FALSE</Enabled>
    </RequestProgress>
</SelectObjectContentRequest>`)
	}
	const maxProcessed = 4 << 20

	// Records are streamed: the error surfaces through the event stream.
	// Evaluate frames mid-stream reader errors as InternalError carrying the
	// reader's message, so match on the OverMaxRecordSize message text.
	t.Run("body", func(t *testing.T) {
		s3Select, err := NewS3Select(bytes.NewReader(reqFor("NONE")))
		if err != nil {
			t.Fatal(err)
		}
		if err := s3Select.Open(newBytesRSC(obj.Bytes())); err != nil {
			t.Fatal(err)
		}
		w := &testResponseWriter{}
		s3Select.Evaluate(w)
		_, processed := s3Select.getProgress()
		s3Select.Close()

		if !bytes.Contains(w.response, []byte("maxCharsPerRecord")) {
			t.Fatalf("expected OverMaxRecordSize message in response (%d compressed bytes, %d processed)", obj.Len(), processed)
		}
		if processed > maxProcessed {
			t.Fatalf("processed %d decompressed bytes, want <= %d", processed, maxProcessed)
		}
	})

	// The header line is read synchronously in Open and must be rejected
	// there with the S3 error code.
	t.Run("header", func(t *testing.T) {
		s3Select, err := NewS3Select(bytes.NewReader(reqFor("USE")))
		if err != nil {
			t.Fatal(err)
		}
		err = s3Select.Open(newBytesRSC(obj.Bytes()))
		_, processed := s3Select.getProgress()
		if err == nil {
			s3Select.Close()
			t.Fatalf("expected Open to fail (%d processed)", processed)
		}
		var serr SelectError
		if !errors.As(err, &serr) || serr.ErrorCode() != "OverMaxRecordSize" || serr.HTTPStatusCode() != 400 {
			t.Fatalf("want OverMaxRecordSize/400, got %v (%T)", err, err)
		}
		if processed > maxProcessed {
			t.Fatalf("processed %d decompressed bytes, want <= %d", processed, maxProcessed)
		}
	})
}

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
	"testing"

	"github.com/klauspost/cpuid/v2"
	"github.com/minio/simdjson-go"
)

// TestJSONLinesCompressedNoNewlineBounded is the JSON Lines sibling of the
// CSV CVE-2026-39414 regression (issue #79): a small GZIP object that
// decompresses into a long run of bytes without any newline must fail with
// OverMaxRecordSize after a bounded amount of decompressed input, instead of
// being buffered whole. Open picks simdjson or the portable json.PReader
// from the host CPU; both paths are exercised by hiding AVX2 from
// simdjson.SupportedCPU for the "preader" subtest.
func TestJSONLinesCompressedNoNewlineBounded(t *testing.T) {
	const decompressed = 64 << 20 // kept small so the pre-fix behavior stays testable
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

	req := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<SelectObjectContentRequest>
    <Expression>SELECT COUNT(*) FROM S3Object</Expression>
    <ExpressionType>SQL</ExpressionType>
    <InputSerialization>
        <CompressionType>GZIP</CompressionType>
        <JSON>
            <Type>LINES</Type>
        </JSON>
    </InputSerialization>
    <OutputSerialization>
        <JSON>
        </JSON>
    </OutputSerialization>
    <RequestProgress>
        <Enabled>FALSE</Enabled>
    </RequestProgress>
</SelectObjectContentRequest>`)
	// The simdjson path reads a 10 MiB block before looking for a newline.
	const maxProcessed = 16 << 20

	run := func(t *testing.T) {
		s3Select, err := NewS3Select(bytes.NewReader(req))
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

		// Records are streamed: the error surfaces through the event stream.
		// Evaluate frames mid-stream reader errors as InternalError carrying the
		// reader's message, so match on the OverMaxRecordSize message text.
		if !bytes.Contains(w.response, []byte("maxCharsPerRecord")) {
			t.Fatalf("expected OverMaxRecordSize message in response (%d compressed bytes, %d processed)", obj.Len(), processed)
		}
		if processed > maxProcessed {
			t.Fatalf("processed %d decompressed bytes, want <= %d", processed, maxProcessed)
		}
	}

	t.Run("native", func(t *testing.T) {
		t.Logf("simdjson.SupportedCPU() = %v", simdjson.SupportedCPU())
		run(t)
	})
	t.Run("preader", func(t *testing.T) {
		if cpuid.CPU.Supports(cpuid.AVX2) {
			cpuid.CPU.Disable(cpuid.AVX2)
			defer cpuid.CPU.Enable(cpuid.AVX2)
		}
		if simdjson.SupportedCPU() {
			t.Fatal("could not force the portable JSON Lines reader")
		}
		run(t)
	})
}

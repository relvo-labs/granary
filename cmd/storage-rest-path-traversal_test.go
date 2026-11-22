// Copyright (c) 2015-2023 MinIO, Inc.
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

package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Synthetic marker stored outside the volume (and outside the drive). Its
// presence in any response proves that a request escaped its volume.
var readMultipleOutsideMarker = []byte("granary-issue74-outside-volume-marker")

// collectReadMultiple runs ReadMultiple and returns every response it sent.
func collectReadMultiple(t *testing.T, disk StorageAPI, req ReadMultipleReq) ([]ReadMultipleResp, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	ch := make(chan ReadMultipleResp, len(req.Files)+1)
	var got []ReadMultipleResp
	done := make(chan struct{})
	go func() {
		defer close(done)
		for r := range ch {
			got = append(got, r)
		}
	}()
	err := disk.ReadMultiple(ctx, req, ch)
	<-done
	return got, err
}

func isPathConfinementErr(err error) bool {
	return errors.Is(err, errFileAccessDenied) ||
		errors.Is(err, errVolumeAccessDenied) ||
		errors.Is(err, errVolumeNotFound)
}

// readMultipleTraversalCases returns requests that must be rejected. secret is
// the base name of a file stored next to the drive directory, other is a
// second volume on the same drive holding the file "victim".
func readMultipleTraversalCases(bucket, secret, secretAbs string) []struct {
	name string
	req  ReadMultipleReq
} {
	cases := []struct {
		name string
		req  ReadMultipleReq
	}{
		{"bucket-dotdot", ReadMultipleReq{Bucket: "..", Files: []string{secret}}},
		{"bucket-nested-dotdot", ReadMultipleReq{Bucket: bucket + "/../..", Files: []string{secret}}},
		{"bucket-dotdot-dotdot", ReadMultipleReq{Bucket: "../..", Files: []string{secret}}},
		{"bucket-rooted-dotdot", ReadMultipleReq{Bucket: "/..", Files: []string{secret}}},
		{"bucket-empty", ReadMultipleReq{Bucket: "", Files: []string{bucket + "/prefix/file1"}}},
		{"prefix-dotdot", ReadMultipleReq{Bucket: bucket, Prefix: "../..", Files: []string{secret}}},
		{"prefix-cross-volume", ReadMultipleReq{Bucket: bucket, Prefix: "../other", Files: []string{"victim"}}},
		{"prefix-absolute", ReadMultipleReq{Bucket: bucket, Prefix: "/prefix", Files: []string{"file1"}}},
		{"file-dotdot", ReadMultipleReq{Bucket: bucket, Files: []string{"../../" + secret}}},
		{"file-cross-volume", ReadMultipleReq{Bucket: bucket, Files: []string{"../other/victim"}}},
		{"file-dotdot-after-valid", ReadMultipleReq{Bucket: bucket, Prefix: "prefix", Files: []string{"file1", "../../../" + secret}}},
		{"file-absolute", ReadMultipleReq{Bucket: bucket, Files: []string{secretAbs}}},
		{"file-dot-segment", ReadMultipleReq{Bucket: bucket, Files: []string{"./prefix/file1"}}},
		{"file-empty", ReadMultipleReq{Bucket: bucket, Files: []string{""}}},
	}
	if runtime.GOOS == "windows" {
		cases = append(cases, struct {
			name string
			req  ReadMultipleReq
		}{"file-backslash-dotdot", ReadMultipleReq{Bucket: bucket, Files: []string{`..\..\` + secret}}})
	}
	return cases
}

func assertReadMultipleRejected(t *testing.T, disk StorageAPI, req ReadMultipleReq) {
	t.Helper()
	got, err := collectReadMultiple(t, disk, req)
	for _, r := range got {
		if bytes.Contains(r.Data, readMultipleOutsideMarker) || bytes.Contains(r.Data, []byte("victim-data")) {
			t.Fatalf("request escaped the volume: response for %q returned out-of-volume data", r.File)
		}
	}
	if !isPathConfinementErr(err) {
		t.Fatalf("expected a path-confinement error, got err=%v with %d responses", err, len(got))
	}
	if len(got) != 0 {
		t.Fatalf("expected no responses for a rejected request, got %d", len(got))
	}
}

func assertReadMultipleNormal(t *testing.T, disk StorageAPI, bucket string) {
	t.Helper()
	got, err := collectReadMultiple(t, disk, ReadMultipleReq{
		Bucket: bucket,
		Prefix: "prefix",
		Files:  []string{"file1", "missing", "sub/file2", "a..b"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []struct {
		file   string
		exists bool
		data   string
	}{
		{"file1", true, "file1-data"},
		{"missing", false, ""},
		{"sub/file2", true, "file2-data"},
		{"a..b", true, "dots-in-name"},
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d responses, got %d: %+v", len(want), len(got), got)
	}
	for i, w := range want {
		r := got[i]
		if r.File != w.file || r.Exists != w.exists || string(r.Data) != w.data || r.Error != "" {
			t.Fatalf("response %d: got file=%q exists=%v data=%q err=%q, want file=%q exists=%v data=%q",
				i, r.File, r.Exists, r.Data, r.Error, w.file, w.exists, w.data)
		}
		if r.Bucket != bucket || r.Prefix != "prefix" {
			t.Fatalf("response %d: got bucket=%q prefix=%q", i, r.Bucket, r.Prefix)
		}
	}
}

// seedReadMultipleVolumes writes the fixtures used by the ReadMultiple tests.
func seedReadMultipleVolumes(t *testing.T, disk StorageAPI, bucket string) {
	t.Helper()
	ctx := t.Context()
	for _, vol := range []string{bucket, "other"} {
		if err := disk.MakeVol(ctx, vol); err != nil && !errors.Is(err, errVolumeExists) {
			t.Fatalf("MakeVol %s: %v", vol, err)
		}
	}
	files := map[string]string{
		"prefix/file1":     "file1-data",
		"prefix/sub/file2": "file2-data",
		"prefix/a..b":      "dots-in-name",
	}
	for p, data := range files {
		if err := disk.WriteAll(ctx, bucket, p, []byte(data)); err != nil {
			t.Fatalf("WriteAll %s: %v", p, err)
		}
	}
	if err := disk.WriteAll(ctx, "other", "victim", []byte("victim-data")); err != nil {
		t.Fatalf("WriteAll victim: %v", err)
	}
}

// TestXLStorageReadMultiplePathConfinement exercises xlStorage.ReadMultiple
// directly, without the storage REST handler (CVE-2026-42600, issue #74).
func TestXLStorageReadMultiplePathConfinement(t *testing.T) {
	root := t.TempDir()
	drive := filepath.Join(root, "drive")
	if err := os.Mkdir(drive, 0o755); err != nil {
		t.Fatal(err)
	}
	secretName := "outside-secret.txt"
	secretAbs := filepath.Join(root, secretName)
	if err := os.WriteFile(secretAbs, readMultipleOutsideMarker, 0o600); err != nil {
		t.Fatal(err)
	}
	xl, err := newLocalXLStorage(drive)
	if err != nil {
		t.Fatalf("newLocalXLStorage: %v", err)
	}
	const bucket = "bkt"
	seedReadMultipleVolumes(t, xl, bucket)

	t.Run("normal-read", func(t *testing.T) {
		assertReadMultipleNormal(t, xl, bucket)
	})
	for _, tc := range readMultipleTraversalCases(bucket, secretName, filepath.ToSlash(secretAbs)) {
		t.Run(tc.name, func(t *testing.T) {
			assertReadMultipleRejected(t, xl, tc.req)
		})
	}
}

// TestStorageRESTClientReadMultiplePathConfinement sends ReadMultiple
// requests through the storage REST client to the storage REST server.
func TestStorageRESTClientReadMultiplePathConfinement(t *testing.T) {
	restClient := newStorageRESTHTTPServerClient(t)
	local := globalLocalSetDrives[0][0][0]
	drive := restClient.endpoint.Path
	secretName := "outside-secret-" + uuid.NewString()
	secretAbs := filepath.Join(filepath.Dir(drive), secretName)
	if err := os.WriteFile(secretAbs, readMultipleOutsideMarker, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(secretAbs) })
	const bucket = "foo"
	seedReadMultipleVolumes(t, local, bucket)

	t.Run("normal-read", func(t *testing.T) {
		assertReadMultipleNormal(t, restClient, bucket)
	})
	for _, tc := range readMultipleTraversalCases(bucket, secretName, filepath.ToSlash(secretAbs)) {
		t.Run(tc.name, func(t *testing.T) {
			assertReadMultipleRejected(t, restClient, tc.req)
		})
	}
}

// TestStorageRESTClientBodyPathConfinement covers the other storage REST
// handlers whose paths arrive in the msgpack request body, which
// setRequestValidityMiddleware does not inspect.
func TestStorageRESTClientBodyPathConfinement(t *testing.T) {
	restClient := newStorageRESTHTTPServerClient(t)
	local := globalLocalSetDrives[0][0][0]
	ctx := t.Context()

	t.Run("DeleteBulk", func(t *testing.T) {
		if err := local.WriteAll(ctx, "bar", "bulk-victim", []byte("victim-data")); err != nil {
			t.Fatal(err)
		}
		if err := local.WriteAll(ctx, "foo", "bulk-own", []byte("own")); err != nil {
			t.Fatal(err)
		}
		err := restClient.DeleteBulk(ctx, "foo", "../bar/bulk-victim")
		if _, rerr := local.ReadAll(ctx, "bar", "bulk-victim"); rerr != nil {
			t.Fatalf("file in another volume was deleted through DeleteBulk (err=%v, read err=%v)", err, rerr)
		}
		if !errors.Is(err, errFileAccessDenied) {
			t.Fatalf("expected errFileAccessDenied, got %v", err)
		}
		// Positive control: a confined path is still deleted.
		if err := restClient.DeleteBulk(ctx, "foo", "bulk-own"); err != nil {
			t.Fatalf("DeleteBulk of a confined path: %v", err)
		}
		if _, err := local.ReadAll(ctx, "foo", "bulk-own"); !errors.Is(err, errFileNotFound) {
			t.Fatalf("expected confined file to be deleted, got %v", err)
		}
	})

	t.Run("ReadParts", func(t *testing.T) {
		pi := ObjectPartInfo{Number: 1, ETag: "victim-etag", Size: 1}
		buf, err := pi.MarshalMsg(nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, vol := range []string{"foo", "bar"} {
			if err := local.WriteAll(ctx, vol, "up/part.1.meta", buf); err != nil {
				t.Fatal(err)
			}
			if err := local.WriteAll(ctx, vol, "up/part.1", []byte("x")); err != nil {
				t.Fatal(err)
			}
		}
		infos, err := restClient.ReadParts(ctx, "foo", "../bar/up/part.1.meta")
		for _, info := range infos {
			if info != nil && info.ETag == "victim-etag" {
				t.Fatalf("ReadParts read part metadata from another volume")
			}
		}
		if !errors.Is(err, errFileAccessDenied) {
			t.Fatalf("expected errFileAccessDenied, got infos=%v err=%v", infos, err)
		}
		// Positive control.
		infos, err = restClient.ReadParts(ctx, "foo", "up/part.1.meta")
		if err != nil || len(infos) != 1 || infos[0].ETag != "victim-etag" || infos[0].Error != "" {
			t.Fatalf("ReadParts of a confined path: infos=%v err=%v", infos, err)
		}
	})

	t.Run("DeleteVersions", func(t *testing.T) {
		fi := FileInfo{
			Volume:    "bar",
			Name:      "dv-obj",
			VersionID: uuid.NewString(),
			ModTime:   time.Now().UTC(),
			Erasure: ErasureInfo{
				Algorithm:    erasureAlgorithm,
				DataBlocks:   1,
				ParityBlocks: 0,
				BlockSize:    blockSizeV2,
				Index:        1,
				Distribution: []int{1},
			},
			Metadata: map[string]string{},
		}
		if err := local.WriteMetadata(ctx, "", "bar", "dv-obj", fi); err != nil {
			t.Fatal(err)
		}
		fi.Volume, fi.Name = "foo", "../bar/dv-obj"
		errs := restClient.DeleteVersions(ctx, "foo", []FileInfoVersions{{
			Volume:   "foo",
			Name:     "../bar/dv-obj",
			Versions: []FileInfo{fi},
		}}, DeleteOptions{})
		if _, rerr := local.ReadXL(ctx, "bar", "dv-obj", false); rerr != nil {
			t.Fatalf("version in another volume was deleted through DeleteVersions (errs=%v, read err=%v)", errs, rerr)
		}
		if len(errs) != 1 || !errors.Is(errs[0], errFileAccessDenied) {
			t.Fatalf("expected [errFileAccessDenied], got %v", errs)
		}
	})
}

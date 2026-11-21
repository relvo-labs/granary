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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Issue #82: the grid (websocket) storage RPCs hand msgpack volume and path
// arguments straight to xlStorage, without setRequestValidityMiddleware.
// These tests place victims both outside the drive and in a second volume
// and check that no xlStorage method reads, writes, renames or deletes them
// through a "..", or absolute, volume or path argument.

var gridConfinementMarker = []byte("granary-issue82-outside-volume-marker")

const (
	gridConfinementBucket = "bkt"
	gridConfinementOther  = "other"
)

// gridConfinementFixture lays out
//
//	root/victim, root/vobj/..., root/emptydir/      (outside the drive)
//	root/drive/other/victim, .../vobj/, .../emptydir (another volume)
//	root/drive/bkt/                                 (the volume used by callers)
type gridConfinementFixture struct {
	root, drive string
	metaBuf     []byte
	fi          FileInfo // version stored in every vobj/xl.meta
	strayDir    string   // unreferenced data dir, removed by CleanAbandonedData
}

func newGridConfinementFixture(t *testing.T, root, drive string) *gridConfinementFixture {
	t.Helper()
	f := &gridConfinementFixture{root: root, drive: drive, strayDir: uuid.NewString()}
	f.fi = FileInfo{
		Volume:    gridConfinementOther,
		Name:      "vobj",
		VersionID: uuid.NewString(),
		DataDir:   uuid.NewString(),
		ModTime:   time.Now().UTC(),
		Size:      int64(len(gridConfinementMarker)),
		Erasure: ErasureInfo{
			Algorithm:    erasureAlgorithm,
			DataBlocks:   1,
			ParityBlocks: 0,
			BlockSize:    blockSizeV2,
			Index:        1,
			Distribution: []int{1},
		},
		Parts: []ObjectPartInfo{{
			Number:     1,
			Size:       int64(len(gridConfinementMarker)),
			ActualSize: int64(len(gridConfinementMarker)),
		}},
		Metadata: map[string]string{},
	}
	var xl xlMetaV2
	if err := xl.AddVersion(f.fi); err != nil {
		t.Fatal(err)
	}
	buf, err := xl.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	f.metaBuf = buf
	for _, d := range []string{filepath.Join(drive, gridConfinementBucket), filepath.Join(drive, gridConfinementOther)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.reseed(t)
	return f
}

// victimDirs are the directories holding victims: outside the drive and
// inside the other volume.
func (f *gridConfinementFixture) victimDirs() []string {
	return []string{f.root, filepath.Join(f.drive, gridConfinementOther)}
}

// reseed restores every victim, so that each subtest starts from the same
// state even when a previous traversal succeeded.
func (f *gridConfinementFixture) reseed(t *testing.T) {
	t.Helper()
	for _, dir := range f.victimDirs() {
		for _, name := range []string{"victim", "vobj", "emptydir", "created", "newvol"} {
			if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
		mustWrite := func(p string, b []byte) {
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		mustWrite(filepath.Join(dir, "victim"), gridConfinementMarker)
		mustWrite(filepath.Join(dir, "vobj", xlStorageFormatFile), f.metaBuf)
		mustWrite(filepath.Join(dir, "vobj", f.fi.DataDir, "part.1"), gridConfinementMarker)
		mustWrite(filepath.Join(dir, "vobj", f.strayDir, "part.1"), gridConfinementMarker)
		if err := os.MkdirAll(filepath.Join(dir, "emptydir"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// An absolute volume used to be joined below the drive; remove what such
	// a request may have created there.
	first := strings.SplitN(strings.TrimPrefix(filepath.ToSlash(f.root), "/"), "/", 2)[0]
	if first != "" && first != gridConfinementBucket && first != gridConfinementOther && first != minioMetaBucket {
		if err := os.RemoveAll(filepath.Join(f.drive, first)); err != nil {
			t.Fatal(err)
		}
	}
}

// snapshot hashes everything below root except the caller's own volume and
// .minio.sys, which legitimate operations may change.
func (f *gridConfinementFixture) snapshot(t *testing.T) map[string]string {
	t.Helper()
	skip := []string{
		filepath.Join(f.drive, gridConfinementBucket),
		filepath.Join(f.drive, minioMetaBucket),
	}
	snap := make(map[string]string)
	err := filepath.WalkDir(f.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if slices.Contains(skip, p) {
			return filepath.SkipDir
		}
		rel, _ := filepath.Rel(f.root, p)
		if d.IsDir() {
			snap[rel] = "dir"
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		snap[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

type gridConfinementCase struct {
	name string
	vol  string
	// path is joined with the victim name chosen by the operation.
	path string
	// mustReject is false only for an absolute path, which is joined below
	// the volume and therefore stays confined; it must not leak either.
	mustReject bool
}

func gridConfinementCases(rootAbs string) []gridConfinementCase {
	b := gridConfinementBucket
	return []gridConfinementCase{
		{"volume-dotdot-escapes-drive", b + "/..", "../", true},
		{"volume-dotdot-dotdot", b + "/../..", "", true},
		{"volume-leading-dotdot", "../drive/..", "", true},
		{"volume-cross-volume", b + "/../" + gridConfinementOther, "", true},
		{"volume-absolute", rootAbs, "", true},
		{"path-dotdot-escapes-drive", b, "../../", true},
		{"path-cross-volume", b, "../" + gridConfinementOther + "/", true},
		{"path-dot-then-dotdot", b, "./../../", true},
		{"path-absolute", b, rootAbs + "/", false},
	}
}

type gridConfinementOp struct {
	name   string
	victim string // name appended to the case path
	grid   bool   // reachable through a grid RPC from the storage REST client
	// volOnly operations take the whole case as one volume argument.
	volOnly bool
	// run performs the operation and reports whether it returned data that
	// lives outside the caller's volume.
	run func(ctx context.Context, f *gridConfinementFixture, disk StorageAPI, vol, p string) (leaked bool, err error)
}

func gridConfinementOps() []gridConfinementOp {
	bkt := gridConfinementBucket
	inlineFI := func(name string) FileInfo {
		return FileInfo{
			Volume:    bkt,
			Name:      name,
			VersionID: uuid.NewString(),
			ModTime:   time.Now().UTC(),
			Size:      1,
			Data:      []byte("x"),
			Erasure: ErasureInfo{
				Algorithm:    erasureAlgorithm,
				DataBlocks:   1,
				BlockSize:    blockSizeV2,
				Index:        1,
				Distribution: []int{1},
			},
			Metadata: map[string]string{},
		}
	}
	partsLeak := func(resp *CheckPartsResp) bool {
		if resp == nil {
			return false
		}
		for _, r := range resp.Results {
			if r == checkPartSuccess || r == checkPartFileCorrupt {
				return true
			}
		}
		return false
	}
	return []gridConfinementOp{
		// Reads.
		{name: "ReadAll", victim: "victim", grid: true, run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			buf, err := d.ReadAll(ctx, vol, p)
			return bytes.Contains(buf, gridConfinementMarker), err
		}},
		{name: "ReadXL", victim: "vobj", grid: true, run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			rf, err := d.ReadXL(ctx, vol, p, false)
			return err == nil && len(rf.Buf) > 0, err
		}},
		{name: "ReadVersion", victim: "vobj", grid: true, run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			_, err := d.ReadVersion(ctx, "", vol, p, "", ReadOptions{})
			return err == nil, err
		}},
		{name: "ReadVersion-origvolume", victim: "vobj", grid: true, run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			_, err := d.ReadVersion(ctx, vol, vol, p, "", ReadOptions{})
			return err == nil, err
		}},
		{name: "ReadFile", victim: "victim", run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			buf := make([]byte, len(gridConfinementMarker))
			n, err := d.ReadFile(ctx, vol, p, 0, buf, nil)
			return bytes.Contains(buf[:max(n, 0)], gridConfinementMarker), err
		}},
		{name: "ReadFileStream", victim: "victim", run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			rc, err := d.ReadFileStream(ctx, vol, p, 0, int64(len(gridConfinementMarker)))
			if err != nil {
				return false, err
			}
			defer rc.Close()
			b, _ := io.ReadAll(rc)
			return bytes.Contains(b, gridConfinementMarker), nil
		}},
		{name: "StatInfoFile", victim: "victim", run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			st, err := d.StatInfoFile(ctx, vol, p, false)
			return len(st) > 0, err
		}},
		{name: "ListDir", victim: "", grid: true, run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			entries, err := d.ListDir(ctx, "", vol, p, -1)
			return slices.Contains(entries, "victim"), err
		}},
		{name: "WalkDir", victim: "", grid: true, run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			var buf bytes.Buffer
			err := d.WalkDir(ctx, WalkDirOptions{Bucket: vol, BaseDir: p, Recursive: true}, &buf)
			names, _ := newMetacacheReader(&buf).readNames(-1)
			for _, n := range names {
				if strings.Contains(n, "vobj") {
					return true, err
				}
			}
			return false, err
		}},
		{name: "CheckParts", victim: "vobj", grid: true, run: func(ctx context.Context, f *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			resp, err := d.CheckParts(ctx, vol, p, f.fi)
			return partsLeak(resp), err
		}},
		{name: "VerifyFile", victim: "vobj", run: func(ctx context.Context, f *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			resp, err := d.VerifyFile(ctx, vol, p, f.fi)
			return partsLeak(resp), err
		}},
		{name: "StatVol", victim: "vobj", grid: true, volOnly: true, run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, _ string) (bool, error) {
			_, err := d.StatVol(ctx, vol)
			return err == nil, err
		}},

		// Writes.
		{name: "WriteAll", victim: "victim", grid: true, run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			return false, d.WriteAll(ctx, vol, p, []byte("overwritten"))
		}},
		{name: "CreateFile", victim: "created", run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			return false, d.CreateFile(ctx, "", vol, p, 7, strings.NewReader("created"))
		}},
		{name: "AppendFile", victim: "victim", run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			return false, d.AppendFile(ctx, vol, p, []byte("appended"))
		}},
		{name: "WriteMetadata", victim: "vobj", grid: true, run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			return false, d.WriteMetadata(ctx, "", vol, p, inlineFI(p))
		}},
		{name: "UpdateMetadata", victim: "vobj", grid: true, run: func(ctx context.Context, f *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			fi := f.fi
			fi.Metadata = map[string]string{"x-granary-issue82": "updated"}
			return false, d.UpdateMetadata(ctx, vol, p, fi, UpdateMetadataOpts{})
		}},
		{name: "MakeVol", victim: "newvol", volOnly: true, run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, _ string) (bool, error) {
			return false, d.MakeVol(ctx, vol)
		}},

		// Renames.
		{name: "RenameFile-src", victim: "victim", grid: true, run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			return false, d.RenameFile(ctx, vol, p, bkt, "stolen-"+uuid.NewString())
		}},
		{name: "RenameFile-dst", victim: "created", grid: true, run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			src := "rename-src-" + uuid.NewString()
			if err := d.WriteAll(ctx, bkt, src, []byte("src")); err != nil {
				return false, err
			}
			return false, d.RenameFile(ctx, bkt, src, vol, p)
		}},
		{name: "RenamePart-src", victim: "victim", grid: true, run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			return false, d.RenamePart(ctx, vol, p, bkt, "stolen-part-"+uuid.NewString(), []byte("meta"), "")
		}},
		{name: "RenamePart-dst", victim: "created", grid: true, run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			src := "part-src-" + uuid.NewString()
			if err := d.WriteAll(ctx, bkt, src, []byte("src")); err != nil {
				return false, err
			}
			return false, d.RenamePart(ctx, bkt, src, vol, p, []byte("meta"), "")
		}},
		{name: "RenameData-src", victim: "vobj", grid: true, run: func(ctx context.Context, f *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			fi := f.fi
			fi.VersionID = uuid.NewString()
			_, err := d.RenameData(ctx, vol, p, fi, bkt, "stolen-obj-"+uuid.NewString(), RenameOptions{})
			return false, err
		}},
		{name: "RenameData-dst", victim: "created", grid: true, run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			_, err := d.RenameData(ctx, minioMetaTmpBucket, uuid.NewString(), inlineFI(p), vol, p, RenameOptions{})
			return false, err
		}},

		// Deletes.
		{name: "Delete", victim: "victim", grid: true, run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			return false, d.Delete(ctx, vol, p, DeleteOptions{})
		}},
		{name: "Delete-recursive", victim: "vobj", grid: true, run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			return false, d.Delete(ctx, vol, p, DeleteOptions{Recursive: true, Immediate: true})
		}},
		{name: "DeleteVersion", victim: "vobj", grid: true, run: func(ctx context.Context, f *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			return false, d.DeleteVersion(ctx, vol, p, f.fi, false, DeleteOptions{})
		}},
		{name: "DeleteVersions", victim: "vobj", run: func(ctx context.Context, f *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			errs := d.DeleteVersions(ctx, vol, []FileInfoVersions{{Volume: vol, Name: p, Versions: []FileInfo{f.fi}}}, DeleteOptions{})
			return false, errs[0]
		}},
		{name: "DeleteBulk", victim: "victim", run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			return false, d.DeleteBulk(ctx, vol, p)
		}},
		{name: "CleanAbandonedData", victim: "vobj", run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, p string) (bool, error) {
			return false, d.CleanAbandonedData(ctx, vol, p)
		}},
		{name: "DeleteVol", victim: "emptydir", volOnly: true, run: func(ctx context.Context, _ *gridConfinementFixture, d StorageAPI, vol, _ string) (bool, error) {
			return false, d.DeleteVol(ctx, vol, false)
		}},
	}
}

func runGridConfinementCases(t *testing.T, f *gridConfinementFixture, disk StorageAPI, gridOnly, strictErr bool) {
	for _, op := range gridConfinementOps() {
		if gridOnly && !op.grid {
			continue
		}
		t.Run(op.name, func(t *testing.T) {
			for _, c := range gridConfinementCases(filepath.ToSlash(f.root)) {
				t.Run(c.name, func(t *testing.T) {
					vol, p := c.vol, c.path+op.victim
					if op.volOnly {
						vol, p = c.vol+"/"+c.path+op.victim, ""
					}
					f.reseed(t)
					before := f.snapshot(t)
					ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
					defer cancel()
					leaked, err := op.run(ctx, f, disk, vol, p)
					after := f.snapshot(t)
					if leaked {
						t.Errorf("%s(vol=%q, path=%q) returned data from outside the volume (err=%v)", op.name, vol, p, err)
					}
					if diff := snapshotDiff(before, after); diff != "" {
						t.Errorf("%s(vol=%q, path=%q) changed files outside the volume (err=%v): %s", op.name, vol, p, err, diff)
					}
					if !c.mustReject {
						return
					}
					if err == nil {
						t.Errorf("%s(vol=%q, path=%q) was accepted", op.name, vol, p)
					} else if strictErr && !isPathConfinementErr(err) {
						t.Errorf("%s(vol=%q, path=%q): expected a path-confinement error, got %v", op.name, vol, p, err)
					}
				})
			}
		})
	}
}

func snapshotDiff(before, after map[string]string) string {
	var diffs []string
	for k, v := range before {
		if av, ok := after[k]; !ok {
			diffs = append(diffs, "removed "+k)
		} else if av != v {
			diffs = append(diffs, "modified "+k)
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			diffs = append(diffs, "created "+k)
		}
	}
	slices.Sort(diffs)
	return strings.Join(diffs, ", ")
}

// TestXLStorageGridPathConfinement calls xlStorage directly, which is what
// every grid storage handler does once the disk ID check passes.
func TestXLStorageGridPathConfinement(t *testing.T) {
	root := t.TempDir()
	drive := filepath.Join(root, "drive")
	if err := os.Mkdir(drive, 0o755); err != nil {
		t.Fatal(err)
	}
	xl, err := newLocalXLStorage(drive)
	if err != nil {
		t.Fatalf("newLocalXLStorage: %v", err)
	}
	f := newGridConfinementFixture(t, root, drive)
	runGridConfinementCases(t, f, xl, false, true)

	// RenamePart's skipParent arrives in the same grid message and bounds
	// the parent directories renameAll creates; it must stay confined too.
	t.Run("RenamePart-skipParent", func(t *testing.T) {
		for _, skipParent := range []string{"../..", "../" + gridConfinementOther, "up/../../.."} {
			src := "part-src-" + uuid.NewString()
			if err := xl.WriteAll(t.Context(), gridConfinementBucket, src, []byte("src")); err != nil {
				t.Fatal(err)
			}
			err := xl.RenamePart(t.Context(), gridConfinementBucket, src, gridConfinementBucket, "up/part.1", []byte("meta"), skipParent)
			if !errors.Is(err, errFileAccessDenied) {
				t.Errorf("RenamePart(skipParent=%q): expected errFileAccessDenied, got %v", skipParent, err)
			}
		}
	})
}

// TestStorageRESTClientGridPathConfinement sends the same requests through
// the storage REST client, so they arrive at the storage server over grid.
func TestStorageRESTClientGridPathConfinement(t *testing.T) {
	restClient := newStorageRESTHTTPServerClient(t)
	drive := restClient.endpoint.Path
	f := newGridConfinementFixture(t, filepath.Dir(drive), drive)
	runGridConfinementCases(t, f, restClient, true, true)
}

// TestXLStoragePathConfinementAllowsInternalPaths checks that the shapes
// internal callers use keep working: .minio.sys/tmp and .minio.sys/multipart
// volumes, healing's bucket/object volumes, trailing slashes, names that
// merely contain dots, and an empty path for listings.
func TestXLStoragePathConfinementAllowsInternalPaths(t *testing.T) {
	t.Run("xlStorage", func(t *testing.T) {
		drive := t.TempDir()
		xl, err := newLocalXLStorage(drive)
		if err != nil {
			t.Fatal(err)
		}
		checkPathConfinementAllowsInternalPaths(t, xl, true)
	})
	t.Run("storageRESTClient", func(t *testing.T) {
		restClient := newStorageRESTHTTPServerClient(t)
		local := globalLocalSetDrives[0][0][0]
		if err := local.MakeVol(t.Context(), gridConfinementBucket); err != nil && !errors.Is(err, errVolumeExists) {
			t.Fatal(err)
		}
		checkPathConfinementAllowsInternalPaths(t, restClient, false)
	})
}

func checkPathConfinementAllowsInternalPaths(t *testing.T, disk StorageAPI, local bool) {
	ctx := t.Context()
	bkt := gridConfinementBucket
	must := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}
	if local {
		must("MakeVol", disk.MakeVol(ctx, bkt))
		if err := disk.MakeVol(ctx, minioMetaMultipartBucket); err != nil && !errors.Is(err, errVolumeExists) {
			t.Fatalf("MakeVol multipart: %v", err)
		}
		// Healing recreates directory objects with MakeVol(bucket/object/).
		must("MakeVol bucket/object", disk.MakeVol(ctx, pathJoin(bkt, "dirobj/")))
		if _, err := disk.StatVol(ctx, pathJoin(bkt, "dirobj/")); err != nil {
			t.Fatalf("StatVol bucket/object: %v", err)
		}
		must("DeleteVol bucket/object", disk.DeleteVol(ctx, pathJoin(bkt, "dirobj/"), false))
	}
	for _, vol := range []string{bkt, minioMetaBucket, minioMetaTmpBucket} {
		if _, err := disk.StatVol(ctx, vol); err != nil {
			t.Fatalf("StatVol %s: %v", vol, err)
		}
	}

	for _, p := range []string{"a..b/c..", ".hidden/x", "dir/sub/file", "dir/trailing/", "...", "a.b"} {
		if strings.HasSuffix(p, "/") {
			continue
		}
		if p == "..." && runtime.GOOS == globalWindowsOSName {
			// Win32 resolves a trailing "..." to its parent (issue #82).
			continue
		}
		must("WriteAll "+p, disk.WriteAll(ctx, bkt, p, []byte(p)))
		buf, err := disk.ReadAll(ctx, bkt, p)
		if err != nil || string(buf) != p {
			t.Fatalf("ReadAll %s: %q %v", p, buf, err)
		}
	}
	entries, err := disk.ListDir(ctx, "", bkt, "", -1)
	if err != nil || !slices.Contains(entries, "a..b/") {
		t.Fatalf("ListDir root: %v %v", entries, err)
	}
	entries, err = disk.ListDir(ctx, "", bkt, "dir/", -1)
	if err != nil || !slices.Contains(entries, "sub/") {
		t.Fatalf("ListDir dir/: %v %v", entries, err)
	}

	// Multipart: tmp -> multipart part rename with a skipParent.
	tmpID := uuid.NewString()
	uploadDir := pathJoin("sha256", uuid.NewString())
	// newMultipartUpload creates the upload directory before any part.
	must("WriteAll upload xl.meta", disk.WriteAll(ctx, minioMetaMultipartBucket, pathJoin(uploadDir, xlStorageFormatFile), []byte("upload")))
	must("WriteAll tmp part", disk.WriteAll(ctx, minioMetaTmpBucket, pathJoin(tmpID, "part.1"), []byte("part")))
	must("RenamePart", disk.RenamePart(ctx, minioMetaTmpBucket, pathJoin(tmpID, "part.1"), minioMetaMultipartBucket, pathJoin(uploadDir, "data", "part.1"), []byte("meta"), uploadDir))
	if buf, err := disk.ReadAll(ctx, minioMetaMultipartBucket, pathJoin(uploadDir, "data", "part.1.meta")); err != nil || string(buf) != "meta" {
		t.Fatalf("ReadAll part.1.meta: %q %v", buf, err)
	}
	must("WriteAll tmp file", disk.WriteAll(ctx, minioMetaTmpBucket, pathJoin(tmpID, "file"), []byte("file")))
	must("RenameFile", disk.RenameFile(ctx, minioMetaTmpBucket, pathJoin(tmpID, "file"), minioMetaMultipartBucket, pathJoin(uploadDir, "file")))
	must("Delete multipart upload", disk.Delete(ctx, minioMetaMultipartBucket, uploadDir+"/", DeleteOptions{Recursive: true, Immediate: true}))

	// Object metadata life cycle through tmp -> bucket RenameData.
	fi := FileInfo{
		Volume:    bkt,
		Name:      "obj",
		VersionID: uuid.NewString(),
		ModTime:   time.Now().UTC(),
		Size:      1,
		Data:      []byte("x"),
		Erasure: ErasureInfo{
			Algorithm:    erasureAlgorithm,
			DataBlocks:   1,
			BlockSize:    blockSizeV2,
			Index:        1,
			Distribution: []int{1},
		},
		Metadata: map[string]string{},
	}
	if _, err := disk.RenameData(ctx, minioMetaTmpBucket, uuid.NewString(), fi, bkt, "dir/obj", RenameOptions{}); err != nil {
		t.Fatalf("RenameData: %v", err)
	}
	if _, err := disk.ReadVersion(ctx, bkt, bkt, "dir/obj", fi.VersionID, ReadOptions{}); err != nil {
		t.Fatalf("ReadVersion: %v", err)
	}
	if _, err := disk.ReadXL(ctx, bkt, "dir/obj", false); err != nil {
		t.Fatalf("ReadXL: %v", err)
	}
	if _, err := disk.CheckParts(ctx, bkt, "dir/obj", fi); err != nil {
		t.Fatalf("CheckParts: %v", err)
	}
	fi.Metadata = map[string]string{"x-granary-issue82": "updated"}
	must("UpdateMetadata", disk.UpdateMetadata(ctx, bkt, "dir/obj", fi, UpdateMetadataOpts{}))
	fi2 := fi
	fi2.VersionID = uuid.NewString()
	fi2.Fresh = false
	must("WriteMetadata", disk.WriteMetadata(ctx, bkt, bkt, "dir/obj", fi2))
	must("DeleteVersion", disk.DeleteVersion(ctx, bkt, "dir/obj", fi2, false, DeleteOptions{}))
	var buf bytes.Buffer
	must("WalkDir", disk.WalkDir(ctx, WalkDirOptions{Bucket: bkt, BaseDir: "dir/", Recursive: true}, &buf))
	names, _ := newMetacacheReader(&buf).readNames(-1)
	if !slices.Contains(names, "dir/obj") {
		t.Fatalf("WalkDir names: %v", names)
	}
	must("DeleteVersion last", disk.DeleteVersion(ctx, bkt, "dir/obj", fi, false, DeleteOptions{}))
	must("Delete dir/", disk.Delete(ctx, bkt, "dir/", DeleteOptions{Recursive: true, Immediate: true}))
}

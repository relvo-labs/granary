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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/minio/madmin-go/v3"
)

// Issue #82 follow-up. TestXLStorageGridPathConfinement varies the primary
// volume and path arguments. The tests below keep those arguments valid and
// put the traversal into a secondary input instead: directories read back
// from xl.meta, request fields such as FileInfo.DataDir, OldDataDir and
// skipParent, the scanner bucket name, and paths that name the volume
// directory itself. Every victim lives in a t.TempDir() tree.

var derivedConfinementMarker = []byte("granary-issue82-derived-victim-marker")

// derivedConfinementDisk is a drive reached either directly or through the
// storage REST client (grid and HTTP storage handlers).
type derivedConfinementDisk struct {
	disk  StorageAPI
	drive string // drive directory
	root  string // parent of the drive; victims live here
	// strict is true when errors arrive unchanged (direct xlStorage).
	strict bool
}

func forEachDerivedConfinementDisk(t *testing.T, fn func(t *testing.T, d derivedConfinementDisk)) {
	t.Run("xlStorage", func(t *testing.T) {
		root := t.TempDir()
		drive := filepath.Join(root, "drive")
		if err := os.Mkdir(drive, 0o755); err != nil {
			t.Fatal(err)
		}
		xl, err := newLocalXLStorage(drive)
		if err != nil {
			t.Fatalf("newLocalXLStorage: %v", err)
		}
		for _, vol := range []string{gridConfinementBucket, gridConfinementOther} {
			if err := xl.MakeVol(t.Context(), vol); err != nil {
				t.Fatal(err)
			}
		}
		fn(t, derivedConfinementDisk{disk: xl, drive: drive, root: root, strict: true})
	})
	t.Run("storageRESTClient", func(t *testing.T) {
		restClient := newStorageRESTHTTPServerClient(t)
		drive := restClient.endpoint.Path
		local := globalLocalSetDrives[0][0][0]
		for _, vol := range []string{gridConfinementBucket, gridConfinementOther} {
			if err := local.MakeVol(t.Context(), vol); err != nil && !errors.Is(err, errVolumeExists) {
				t.Fatal(err)
			}
		}
		fn(t, derivedConfinementDisk{disk: restClient, drive: drive, root: filepath.Dir(drive)})
	})
}

func derivedMustWrite(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// derivedVictim creates root/victim-<uuid>/ holding part.1, part.1.meta,
// xl.meta.bkp and keep, and returns its base name.
func derivedVictim(t *testing.T, root string) string {
	t.Helper()
	name := "victim-" + uuid.NewString()
	dir := filepath.Join(root, name)
	partMeta, err := (&ObjectPartInfo{Number: 77, ETag: string(derivedConfinementMarker)}).MarshalMsg(nil)
	if err != nil {
		t.Fatal(err)
	}
	derivedMustWrite(t, filepath.Join(dir, "part.1"), derivedConfinementMarker)
	derivedMustWrite(t, filepath.Join(dir, "part.1.meta"), partMeta)
	derivedMustWrite(t, filepath.Join(dir, xlStorageFormatFileBackup), derivedConfinementMarker)
	derivedMustWrite(t, filepath.Join(dir, "keep"), derivedConfinementMarker)
	return name
}

// requireDerivedVictimIntact fails unless every victim file is unchanged.
func requireDerivedVictimIntact(t *testing.T, root, name, what string) {
	t.Helper()
	for _, f := range []string{"part.1", xlStorageFormatFileBackup, "keep"} {
		b, err := os.ReadFile(filepath.Join(root, name, f))
		if err != nil || !bytes.Equal(b, derivedConfinementMarker) {
			t.Errorf("%s: victim %s/%s outside the volume was changed (read err=%v)", what, name, f, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, name, "part.1.meta")); err != nil {
		t.Errorf("%s: victim %s/part.1.meta outside the volume was changed: %v", what, name, err)
	}
}

func derivedLegacyObject(dataDir string) *xlMetaV1Object {
	n := int64(len(derivedConfinementMarker))
	return &xlMetaV1Object{
		Version: xlMetaVersion101,
		Format:  xlMetaFormat,
		Stat:    StatInfo{Size: n, ModTime: time.Now().UTC()},
		Erasure: ErasureInfo{
			Algorithm:    erasureAlgorithm,
			DataBlocks:   1,
			ParityBlocks: 0,
			BlockSize:    blockSizeV2,
			Index:        1,
			Distribution: []int{1},
		},
		Parts:     []ObjectPartInfo{{Number: 1, Size: n, ActualSize: n}},
		VersionID: nullVersionID,
		DataDir:   dataDir,
	}
}

// poisonedLegacyJSON is a pre-xl.meta (xl.json style) legacy document that
// xlStorage converts on load. Its dataDir names a directory outside the drive.
func poisonedLegacyJSON(t *testing.T, dataDir string) []byte {
	t.Helper()
	b, err := json.Marshal(derivedLegacyObject(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// poisonedLegacyXL2 is an indexed xl.meta whose only version is a legacy
// object with a traversal data directory. addVersion would reject it, so the
// version is inserted directly, as a crafted file would be.
func poisonedLegacyXL2(t *testing.T, dataDir string) []byte {
	t.Helper()
	ver := xlMetaV2Version{Type: LegacyType, ObjectV1: derivedLegacyObject(dataDir), WrittenByVersion: globalVersionUnix}
	enc, err := ver.MarshalMsg(nil)
	if err != nil {
		t.Fatal(err)
	}
	x := xlMetaV2{metaV: xlMetaVersion}
	x.versions = []xlMetaV2ShallowVersion{{header: ver.header(), meta: enc}}
	b, err := x.AppendTo(nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestXLStorageMetadataDataDirConfinement writes a well-formed xl.meta whose
// legacy data directory is "../../../victim" through WriteAll (a grid RPC with
// valid arguments). DeleteVersion, DeleteVersions and ReadVersion join that
// directory below the object; none of them may touch or return the victim.
func TestXLStorageMetadataDataDirConfinement(t *testing.T) {
	forEachDerivedConfinementDisk(t, func(t *testing.T, d derivedConfinementDisk) {
		ctx := t.Context()
		bkt := gridConfinementBucket
		encodings := []struct {
			name string
			meta func(t *testing.T, dataDir string) []byte
		}{
			{"legacy-json", poisonedLegacyJSON},
			{"xl2-legacy-version", poisonedLegacyXL2},
		}
		ops := []struct {
			name string
			run  func(ctx context.Context, obj string) (leaked bool, err error)
		}{
			{"DeleteVersion", func(ctx context.Context, obj string) (bool, error) {
				return false, d.disk.DeleteVersion(ctx, bkt, obj, FileInfo{Volume: bkt, Name: obj}, false, DeleteOptions{})
			}},
			{"DeleteVersions", func(ctx context.Context, obj string) (bool, error) {
				errs := d.disk.DeleteVersions(ctx, bkt, []FileInfoVersions{{
					Volume: bkt, Name: obj,
					Versions: []FileInfo{{Volume: bkt, Name: obj}},
				}}, DeleteOptions{})
				return false, errors.Join(errs...)
			}},
			{"ReadVersion-ReadData", func(ctx context.Context, obj string) (bool, error) {
				fi, err := d.disk.ReadVersion(ctx, "", bkt, obj, "", ReadOptions{ReadData: true})
				return bytes.Contains(fi.Data, derivedConfinementMarker), err
			}},
		}
		for _, enc := range encodings {
			for _, op := range ops {
				t.Run(enc.name+"/"+op.name, func(t *testing.T) {
					victim := derivedVictim(t, d.root)
					obj := "obj-" + uuid.NewString()
					// drive/bkt/obj/../../../victim == root/victim
					meta := enc.meta(t, "../../../"+victim)
					if err := d.disk.WriteAll(ctx, bkt, pathJoin(obj, xlStorageFormatFile), meta); err != nil {
						t.Fatalf("WriteAll poisoned xl.meta: %v", err)
					}
					cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
					defer cancel()
					leaked, err := op.run(cctx, obj)
					if leaked {
						t.Errorf("%s returned data from outside the drive (err=%v)", op.name, err)
					}
					requireDerivedVictimIntact(t, d.root, victim, op.name)
					if err == nil {
						t.Errorf("%s accepted an xl.meta with data directory ../../../%s", op.name, victim)
					}
				})
			}
		}
	})
}

// TestXLStorageVolumeRootTargets sends file operations whose path names the
// volume directory itself ("", "/", "//"). CreateFile into .minio.sys/tmp used
// to fail to open the directory and then remove its parent, .minio.sys.
// Nothing outside the target, and no volume directory, may be removed.
func TestXLStorageVolumeRootTargets(t *testing.T) {
	forEachDerivedConfinementDisk(t, func(t *testing.T, d derivedConfinementDisk) {
		bkt, other := gridConfinementBucket, gridConfinementOther
		sentinels := []string{
			filepath.Join(d.drive, minioMetaBucket, "granary-issue82-sentinel"),
			filepath.Join(d.drive, minioMetaBucket, "buckets", "granary-issue82-sentinel"),
			filepath.Join(d.drive, minioMetaTmpBucket, "inflight-"+uuid.NewString(), "part.1"),
			filepath.Join(d.drive, bkt, "keep"),
			filepath.Join(d.drive, other, "keep"),
		}
		seed := func(t *testing.T) {
			for _, s := range sentinels {
				derivedMustWrite(t, s, derivedConfinementMarker)
			}
		}
		check := func(t *testing.T, what string) {
			t.Helper()
			for _, s := range sentinels {
				b, err := os.ReadFile(s)
				if err != nil || !bytes.Equal(b, derivedConfinementMarker) {
					rel, _ := filepath.Rel(d.drive, s)
					t.Errorf("%s: sentinel %s was removed or changed (read err=%v)", what, rel, err)
				}
			}
		}
		data := []byte("data")
		inline := FileInfo{
			Volume: bkt, Name: "obj", VersionID: uuid.NewString(), ModTime: time.Now().UTC(),
			Size: 1, Data: []byte("x"),
			Erasure:  ErasureInfo{Algorithm: erasureAlgorithm, DataBlocks: 1, BlockSize: blockSizeV2, Index: 1, Distribution: []int{1}},
			Metadata: map[string]string{},
		}
		ops := []struct {
			name string
			run  func(ctx context.Context, p string) error
		}{
			{"CreateFile-tmp", func(ctx context.Context, p string) error {
				return d.disk.CreateFile(ctx, "", minioMetaTmpBucket, p, int64(len(data)), bytes.NewReader(data))
			}},
			{"CreateFile-bucket", func(ctx context.Context, p string) error {
				return d.disk.CreateFile(ctx, "", bkt, p, int64(len(data)), bytes.NewReader(data))
			}},
			{"WriteAll-tmp", func(ctx context.Context, p string) error {
				return d.disk.WriteAll(ctx, minioMetaTmpBucket, p, data)
			}},
			{"AppendFile-tmp", func(ctx context.Context, p string) error {
				return d.disk.AppendFile(ctx, minioMetaTmpBucket, p, data)
			}},
			{"DeleteBulk-bucket", func(ctx context.Context, p string) error {
				return d.disk.DeleteBulk(ctx, bkt, p)
			}},
			{"Delete-bucket-recursive", func(ctx context.Context, p string) error {
				return d.disk.Delete(ctx, bkt, p, DeleteOptions{Recursive: true, Immediate: true})
			}},
			{"RenameFile-src", func(ctx context.Context, p string) error {
				dst := "moved"
				if p != "" {
					dst += "/"
				}
				return d.disk.RenameFile(ctx, bkt, p, other, dst)
			}},
			{"RenameFile-dst", func(ctx context.Context, p string) error {
				src := "src-" + uuid.NewString()
				if p != "" {
					src += "/"
					if err := os.MkdirAll(filepath.Join(d.drive, bkt, src), 0o755); err != nil {
						return err
					}
				} else if err := d.disk.WriteAll(ctx, bkt, src, data); err != nil {
					return err
				}
				return d.disk.RenameFile(ctx, bkt, src, other, p)
			}},
			{"RenamePart-dst", func(ctx context.Context, p string) error {
				src := "part-" + uuid.NewString()
				if err := d.disk.WriteAll(ctx, minioMetaTmpBucket, src, data); err != nil {
					return err
				}
				return d.disk.RenamePart(ctx, minioMetaTmpBucket, src, bkt, p, []byte("meta"), "")
			}},
			{"RenameData-src", func(ctx context.Context, p string) error {
				_, err := d.disk.RenameData(ctx, minioMetaTmpBucket, p, inline, bkt, "obj-"+uuid.NewString(), RenameOptions{})
				return err
			}},
			{"RenameData-dst", func(ctx context.Context, p string) error {
				_, err := d.disk.RenameData(ctx, minioMetaTmpBucket, uuid.NewString(), inline, bkt, p, RenameOptions{})
				return err
			}},
		}
		// Operations whose only safe outcome for a volume-root path is an
		// error; Delete already treats the volume root as a no-op.
		mustFail := map[string]bool{
			"CreateFile-tmp": true, "CreateFile-bucket": true, "WriteAll-tmp": true, "AppendFile-tmp": true,
			"DeleteBulk-bucket": true, "RenameFile-src": true, "RenameFile-dst": true, "RenamePart-dst": true,
			"RenameData-src": true, "RenameData-dst": true,
		}
		for _, op := range ops {
			for _, p := range []string{"", "/", "//"} {
				t.Run(op.name+"/"+map[string]string{"": "empty", "/": "slash", "//": "double-slash"}[p], func(t *testing.T) {
					seed(t)
					ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
					defer cancel()
					err := op.run(ctx, p)
					check(t, op.name)
					if !mustFail[op.name] {
						return
					}
					if err == nil {
						t.Errorf("%s(path=%q) was accepted", op.name, p)
					} else if d.strict && !isPathConfinementErr(err) {
						t.Errorf("%s(path=%q): expected a path-confinement error, got %v", op.name, p, err)
					}
				})
			}
		}

		// A failed CreateFile cleans up its parent directory; that must stay
		// below .minio.sys/tmp, even for a single-segment name.
		t.Run("CreateFile-tmp-failed-write-cleanup", func(t *testing.T) {
			seed(t)
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			err := d.disk.CreateFile(ctx, "", minioMetaTmpBucket, "single-"+uuid.NewString(), 64, bytes.NewReader(data))
			if err == nil {
				t.Errorf("CreateFile with a short body was accepted")
			}
			check(t, "CreateFile failed write")
		})
	})
}

// TestXLStorageSecondaryFieldConfinement keeps volume and path valid and
// puts a traversal in a secondary request field.
func TestXLStorageSecondaryFieldConfinement(t *testing.T) {
	forEachDerivedConfinementDisk(t, func(t *testing.T, d derivedConfinementDisk) {
		ctx := t.Context()
		bkt := gridConfinementBucket
		// seedObject stores a valid object with one version in bkt/<name>.
		seedObject := func(t *testing.T) (string, FileInfo) {
			t.Helper()
			name := "sobj-" + uuid.NewString()
			fi := FileInfo{
				Volume: bkt, Name: name, VersionID: uuid.NewString(), DataDir: uuid.NewString(),
				ModTime: time.Now().UTC(), Size: int64(len(derivedConfinementMarker)),
				Erasure: ErasureInfo{Algorithm: erasureAlgorithm, DataBlocks: 1, BlockSize: blockSizeV2, Index: 1, Distribution: []int{1}},
				Parts: []ObjectPartInfo{{
					Number: 1, Size: int64(len(derivedConfinementMarker)), ActualSize: int64(len(derivedConfinementMarker)),
				}},
				Metadata: map[string]string{},
			}
			var xl xlMetaV2
			if err := xl.AddVersion(fi); err != nil {
				t.Fatal(err)
			}
			buf, err := xl.AppendTo(nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := d.disk.WriteAll(ctx, bkt, pathJoin(name, xlStorageFormatFile), buf); err != nil {
				t.Fatal(err)
			}
			if err := d.disk.WriteAll(ctx, bkt, pathJoin(name, fi.DataDir, "part.1"), derivedConfinementMarker); err != nil {
				t.Fatal(err)
			}
			return name, fi
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
		cases := []struct {
			name string
			// localOnly cases set a field that the grid client does not
			// send: DeleteVersionHandler always passes empty
			// DeleteOptions, so OldDataDir is reachable only in-process.
			localOnly bool
			run       func(ctx context.Context, victim string) (leaked bool, err error)
		}{
			{"DeleteVersion-OldDataDir", true, func(ctx context.Context, victim string) (bool, error) {
				name, fi := seedObject(t)
				return false, d.disk.DeleteVersion(ctx, bkt, name, fi, false, DeleteOptions{
					UndoWrite: true, OldDataDir: "../../../" + victim,
				})
			}},
			{"CheckParts-FI.DataDir", false, func(ctx context.Context, victim string) (bool, error) {
				name, fi := seedObject(t)
				fi.DataDir = "../../../" + victim
				resp, err := d.disk.CheckParts(ctx, bkt, name, fi)
				return partsLeak(resp), err
			}},
			{"VerifyFile-FI.DataDir", false, func(ctx context.Context, victim string) (bool, error) {
				name, fi := seedObject(t)
				fi.DataDir = "../../../" + victim
				resp, err := d.disk.VerifyFile(ctx, bkt, name, fi)
				return partsLeak(resp), err
			}},
			{"RenameData-FI.DataDir", false, func(ctx context.Context, victim string) (bool, error) {
				src := uuid.NewString()
				fi := FileInfo{
					Volume: bkt, Name: "dobj", VersionID: uuid.NewString(), DataDir: "../../../../" + victim,
					ModTime: time.Now().UTC(), Size: 1,
					Erasure:  ErasureInfo{Algorithm: erasureAlgorithm, DataBlocks: 1, BlockSize: blockSizeV2, Index: 1, Distribution: []int{1}},
					Parts:    []ObjectPartInfo{{Number: 1, Size: 1, ActualSize: 1}},
					Metadata: map[string]string{},
				}
				_, err := d.disk.RenameData(ctx, minioMetaTmpBucket, src, fi, bkt, "dobj-"+uuid.NewString(), RenameOptions{})
				return false, err
			}},
			{"ReadParts-second-path", false, func(ctx context.Context, victim string) (bool, error) {
				name, _ := seedObject(t)
				parts, err := d.disk.ReadParts(ctx, bkt, pathJoin(name, "part.1.meta"), "../../"+victim+"/part.1.meta")
				for _, p := range parts {
					if p != nil && p.ETag == string(derivedConfinementMarker) {
						return true, err
					}
				}
				return false, err
			}},
			{"RenamePart-SkipParent", false, func(ctx context.Context, victim string) (bool, error) {
				src := "part-src-" + uuid.NewString()
				if err := d.disk.WriteAll(ctx, minioMetaTmpBucket, src, []byte("src")); err != nil {
					return false, err
				}
				return false, d.disk.RenamePart(ctx, minioMetaTmpBucket, src, bkt, "up-"+uuid.NewString()+"/part.1", []byte("meta"), "../../"+victim)
			}},
			{"NSScanner-bucket", false, func(ctx context.Context, victim string) (bool, error) {
				updates := make(chan dataUsageEntry, 1)
				done := make(chan struct{})
				go func() {
					defer close(done)
					for range updates {
					}
				}()
				cache := dataUsageCache{Info: dataUsageCacheInfo{Name: bkt + "/../../" + victim, NextCycle: 1}}
				_, err := d.disk.NSScanner(ctx, cache, updates, madmin.HealNormalScan, nil)
				<-done
				return false, err
			}},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				victim := derivedVictim(t, d.root)
				cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				leaked, err := c.run(cctx, victim)
				if leaked {
					t.Errorf("%s returned data from outside the volume (err=%v)", c.name, err)
				}
				requireDerivedVictimIntact(t, d.root, victim, c.name)
				if c.localOnly && !d.strict {
					// The field never reaches the server; only the
					// victim check above applies.
					return
				}
				if err == nil {
					t.Errorf("%s accepted a traversal in a secondary field", c.name)
				} else if d.strict && !isPathConfinementErr(err) {
					t.Errorf("%s: expected a path-confinement error, got %v", c.name, err)
				}
			})
		}
	})
}

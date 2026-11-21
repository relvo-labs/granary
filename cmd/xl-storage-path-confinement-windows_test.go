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

// Windows also treats '\' as a path separator, and Win32 path normalization
// drops trailing dots and spaces, so a segment made only of dots and spaces
// names its parent. The guards take the platform rule as an argument so the
// Windows decisions are tested on every platform (issue #82).

func TestDrivePathArgsWindowsRules(t *testing.T) {
	cases := []struct {
		path       string
		fileTarget bool
		// deny on Windows / on other platforms
		windows, posix bool
	}{
		// Volume-root targets spelled with backslashes or mixed separators.
		{`\`, true, true, false},
		{`\\`, true, true, false},
		{`\/`, true, true, false},
		{`/\`, true, true, false},
		{`\/\`, true, true, false},
		{`//\\//`, true, true, false},
		{"", true, true, true},
		{"/", true, true, true},
		// The same paths are allowed where the volume itself is valid.
		{`\`, false, false, false},
		{`\/`, false, false, false},
		// Dot segments behind backslashes are rejected everywhere.
		{`..\x`, false, true, true},
		{`x\..\..\y`, false, true, true},
		{`.\x`, false, true, true},
		{`x/..\`, true, true, true},
		// Win32 drops trailing dots and spaces: these name a parent.
		{"...", true, true, false},
		{"x/...", true, true, false},
		{`x\...`, true, true, false},
		{".../x", true, true, false},
		{"x/ ", true, true, false},
		{"x/. .", true, true, false},
		{`x\.. \y`, false, true, true},
		// Drive-relative, drive-absolute and alternate data stream names.
		{"C:x", true, true, false},
		{`C:\x`, true, true, false},
		{"x/C:", true, true, false},
		{"x::$DATA", true, true, false},
		{"x/::$INDEX_ALLOCATION", true, true, false},
		// Ordinary names stay valid on both.
		{"x", true, false, false},
		{"a/b/part.1", true, false, false},
		{"a.b", true, false, false},
		{"a..b/c..", true, false, false},
		{".hidden/x", true, false, false},
		{`\/x`, true, false, false},
		{`x\y`, true, false, false},
		{`\\srv\share\x`, true, false, false},
	}
	for _, c := range cases {
		for _, windows := range []bool{true, false} {
			want := c.posix
			if windows {
				want = c.windows
			}
			err := checkDrivePathArgs(windows, c.fileTarget, c.path)
			if want && !errors.Is(err, errFileAccessDenied) {
				t.Errorf("checkDrivePathArgs(windows=%v, fileTarget=%v, %q) = %v, want errFileAccessDenied", windows, c.fileTarget, c.path, err)
			}
			if !want && err != nil {
				t.Errorf("checkDrivePathArgs(windows=%v, fileTarget=%v, %q) = %v, want nil", windows, c.fileTarget, c.path, err)
			}
		}
	}
}

func TestConfinedDrivePathJoinWindowsRules(t *testing.T) {
	drives := []string{`C:\data\d1`, "/data/d1"}
	cases := []struct {
		volume         string
		windows, posix bool // deny
	}{
		{`\`, true, true},
		{`\bkt`, true, true},
		{`\\srv\share`, true, true},
		{"//srv/share", true, true},
		{`bkt\..`, true, true},
		{`bkt\..\..`, true, true},
		{`.minio.sys\..\x`, true, true},
		{"C:", true, false},
		{`C:\x`, true, false},
		{"C:bkt", true, false},
		{"...", true, false},
		{"bkt/...", true, false},
		{`bkt\. .`, true, false},
		{"bkt", false, false},
		{".minio.sys/tmp", false, false},
		{`bkt\`, false, false},
		{"bkt/dirobj/", false, false},
	}
	for _, drive := range drives {
		for _, c := range cases {
			for _, windows := range []bool{true, false} {
				want := c.posix
				if windows {
					want = c.windows
				}
				_, err := confinedDrivePathJoin(windows, errVolumeAccessDenied, drive, c.volume)
				if want && !errors.Is(err, errVolumeAccessDenied) {
					t.Errorf("confinedDrivePathJoin(windows=%v, %q, %q) = %v, want errVolumeAccessDenied", windows, drive, c.volume, err)
				}
				if !want && err != nil {
					t.Errorf("confinedDrivePathJoin(windows=%v, %q, %q) = %v, want nil", windows, drive, c.volume, err)
				}
			}
		}
	}
}

// TestCreateFileCleanupDirWindowsRules checks the directory a failed tmp
// CreateFile removes. It must be strictly below the tmp volume as the drive
// filesystem resolves it.
func TestCreateFileCleanupDirWindowsRules(t *testing.T) {
	for _, drive := range []string{`C:\data\d1`, "/data/d1"} {
		volumeDir := pathJoin(drive, minioMetaTmpBucket)
		cases := []struct {
			path string
			// cleanup allowed on Windows / on other platforms
			windows, posix bool
		}{
			{`\/x`, false, true},
			{`\\/x`, false, true},
			{`\x`, false, false},
			{`x\y`, true, false},
			{`/\/x`, false, true},
			{`.../x`, false, true},
			{`x. /y`, true, true},
			{"x", false, false},
			{"upload/part.1", true, true},
			{"upload/data/part.1", true, true},
		}
		for _, c := range cases {
			filePath := pathJoin(volumeDir, c.path)
			for _, windows := range []bool{true, false} {
				want := c.posix
				if windows {
					want = c.windows
				}
				dir, ok := tmpCleanupDir(volumeDir, filePath, windows)
				if ok != want {
					t.Errorf("tmpCleanupDir(windows=%v, %q, %q) = %q, %v; want ok=%v", windows, volumeDir, filePath, dir, ok, want)
				}
				if ok && !isStrictlyBelowDrive(dir, volumeDir, windows) {
					t.Errorf("tmpCleanupDir(windows=%v, %q, %q) = %q, not strictly below the volume", windows, volumeDir, filePath, dir)
				}
			}
		}
	}
}

// TestDeleteFileTargetWindowsRules checks deleteFile's bound: it trashes or
// removes deletePath only when that is strictly below basePath.
func TestDeleteFileTargetWindowsRules(t *testing.T) {
	for _, drive := range []string{`C:\data\d1`, "/data/d1"} {
		base := pathJoin(drive, "bkt")
		cases := []struct {
			deletePath     string
			windows, posix bool // allowed
		}{
			{pathJoin(base, `\`), false, true},
			{pathJoin(base, `\\`), false, true},
			{base + `\`, false, false},
			{pathJoin(base, `\/\`), false, true},
			{pathJoin(base, "..."), false, true},
			{pathJoin(base, "x"), true, true},
			{pathJoin(base, `x\`), true, true},
			{pathJoin(base, `x\y`), true, true},
			{pathJoin(base, "x/"), true, true},
			{base, false, false},
			{base + "/", false, false},
			{pathJoin(drive, "bkt2", "x"), false, false},
		}
		for _, c := range cases {
			for _, windows := range []bool{true, false} {
				want := c.posix
				if windows {
					want = c.windows
				}
				if got := isDeleteFileTarget(base, c.deletePath, windows); got != want {
					t.Errorf("isDeleteFileTarget(windows=%v, %q, %q) = %v, want %v", windows, base, c.deletePath, got, want)
				}
			}
		}
	}
}

// TestXLStorageWindowsSeparatorTargets sends volume-root and parent-naming
// paths spelled with backslashes, mixed separators and Windows trailing-dot
// segments to xlStorage, directly and over the storage REST client. On every
// platform the .minio.sys, in-flight upload and bucket sentinels must
// survive. On Windows, where those paths name the volume or a parent, every
// file-target operation must also be rejected.
func TestXLStorageWindowsSeparatorTargets(t *testing.T) {
	onWindows := runtime.GOOS == globalWindowsOSName
	forEachDerivedConfinementDisk(t, func(t *testing.T, d derivedConfinementDisk) {
		bkt, other := gridConfinementBucket, gridConfinementOther
		sentinels := []string{
			filepath.Join(d.drive, minioMetaBucket, "granary-issue82-sentinel"),
			filepath.Join(d.drive, minioMetaBucket, "buckets", "granary-issue82-sentinel"),
			filepath.Join(d.drive, minioMetaTmpBucket, "inflight-"+uuid.NewString(), "part.1"),
			filepath.Join(d.drive, minioMetaTmpBucket, ".trash", "granary-issue82-sentinel"),
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
			// fileTarget operations must fail on Windows; Delete treats
			// the volume root as a no-op.
			fileTarget bool
			run        func(ctx context.Context, p string) error
		}{
			{"CreateFile-tmp-short-body", true, func(ctx context.Context, p string) error {
				return d.disk.CreateFile(ctx, "", minioMetaTmpBucket, p, 64, bytes.NewReader(data))
			}},
			{"CreateFile-tmp", true, func(ctx context.Context, p string) error {
				return d.disk.CreateFile(ctx, "", minioMetaTmpBucket, p, int64(len(data)), bytes.NewReader(data))
			}},
			{"WriteAll-tmp", true, func(ctx context.Context, p string) error {
				return d.disk.WriteAll(ctx, minioMetaTmpBucket, p, data)
			}},
			{"AppendFile-tmp", true, func(ctx context.Context, p string) error {
				return d.disk.AppendFile(ctx, minioMetaTmpBucket, p, data)
			}},
			{"DeleteBulk-tmp", true, func(ctx context.Context, p string) error {
				return d.disk.DeleteBulk(ctx, minioMetaTmpBucket, p)
			}},
			{"Delete-tmp-recursive", false, func(ctx context.Context, p string) error {
				return d.disk.Delete(ctx, minioMetaTmpBucket, p, DeleteOptions{Recursive: true, Immediate: true})
			}},
			{"Delete-bucket-recursive", false, func(ctx context.Context, p string) error {
				return d.disk.Delete(ctx, bkt, p, DeleteOptions{Recursive: true, Immediate: true})
			}},
			{"RenameFile-src", true, func(ctx context.Context, p string) error {
				return d.disk.RenameFile(ctx, bkt, p, other, "moved-"+uuid.NewString()+"/")
			}},
			{"RenameFile-dst", true, func(ctx context.Context, p string) error {
				src := "src-" + uuid.NewString()
				if err := d.disk.WriteAll(ctx, bkt, src, data); err != nil {
					return err
				}
				return d.disk.RenameFile(ctx, bkt, src, other, p)
			}},
			{"RenamePart-dst", true, func(ctx context.Context, p string) error {
				src := "part-" + uuid.NewString()
				if err := d.disk.WriteAll(ctx, minioMetaTmpBucket, src, data); err != nil {
					return err
				}
				return d.disk.RenamePart(ctx, minioMetaTmpBucket, src, bkt, p, []byte("meta"), "")
			}},
			{"RenameData-src", true, func(ctx context.Context, p string) error {
				_, err := d.disk.RenameData(ctx, minioMetaTmpBucket, p, inline, bkt, "obj-"+uuid.NewString(), RenameOptions{})
				return err
			}},
			{"RenameData-dst", true, func(ctx context.Context, p string) error {
				_, err := d.disk.RenameData(ctx, minioMetaTmpBucket, uuid.NewString(), inline, bkt, p, RenameOptions{})
				return err
			}},
		}
		payloads := map[string]string{
			"backslash":          `\`,
			"double-backslash":   `\\`,
			"backslash-slash":    `\/`,
			"slash-backslash":    `/\`,
			"backslash-slash-x":  `\/x`,
			"slash-backslash-x":  `/\/x`,
			"trailing-dots":      "...",
			"trailing-dots-x":    ".../x",
			"backslash-dots":     `\...`,
			"trailing-dot-space": "x/. .",
		}
		// Payloads whose effective target on Windows is the volume or
		// whose cleanup parent is the volume.
		for _, op := range ops {
			for pname, p := range payloads {
				t.Run(op.name+"/"+pname, func(t *testing.T) {
					seed(t)
					ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
					defer cancel()
					err := op.run(ctx, p)
					check(t, op.name)
					if !onWindows || !op.fileTarget {
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
		// Volume names spelled with backslashes or trailing-dot segments.
		for vname, vol := range map[string]string{
			"backslash-volume":       `\`,
			"backslash-meta-dotdot":  `.minio.sys\..`,
			"drive-letter-volume":    `C:`,
			"trailing-dots-volume":   "...",
			"bucket-dots-volume":     "bkt/...",
			"unc-volume":             `\\srv\share`,
			"backslash-tmp-traverse": `.minio.sys\tmp\..\..`,
		} {
			t.Run("DeleteVol-force/"+vname, func(t *testing.T) {
				seed(t)
				err := d.disk.DeleteVol(t.Context(), vol, true)
				check(t, "DeleteVol")
				if onWindows && err == nil {
					t.Errorf("DeleteVol(%q) was accepted", vol)
				}
			})
		}
	})
}

// TestXLStoragePosixBackslashNamesAllowed is the positive control: outside
// Windows '\' is an ordinary character that S3 object names may contain,
// so such names keep working and a failed tmp CreateFile still cleans up
// its own upload directory.
func TestXLStoragePosixBackslashNamesAllowed(t *testing.T) {
	if runtime.GOOS == globalWindowsOSName {
		t.Skip("'\\' is a path separator on Windows")
	}
	forEachDerivedConfinementDisk(t, func(t *testing.T, d derivedConfinementDisk) {
		ctx := t.Context()
		bkt := gridConfinementBucket
		for _, p := range []string{`a\b`, `dir\sub/file`, `x\..y`, `\lead`} {
			if err := d.disk.WriteAll(ctx, bkt, p, []byte(p)); err != nil {
				t.Fatalf("WriteAll %q: %v", p, err)
			}
			buf, err := d.disk.ReadAll(ctx, bkt, p)
			if err != nil || string(buf) != p {
				t.Fatalf("ReadAll %q: %q %v", p, buf, err)
			}
			if err := d.disk.Delete(ctx, bkt, p, DeleteOptions{}); err != nil {
				t.Fatalf("Delete %q: %v", p, err)
			}
		}
		upload := `up\` + uuid.NewString()
		err := d.disk.CreateFile(ctx, "", minioMetaTmpBucket, upload+"/part.1", 64, bytes.NewReader([]byte("short")))
		if err == nil {
			t.Fatal("CreateFile with a short body was accepted")
		}
		if _, err := os.Stat(filepath.Join(d.drive, minioMetaTmpBucket, upload)); !os.IsNotExist(err) {
			t.Fatalf("failed CreateFile did not clean up %q: %v", upload, err)
		}
		if _, err := os.Stat(filepath.Join(d.drive, minioMetaTmpBucket)); err != nil {
			t.Fatalf("tmp volume: %v", err)
		}
	})
}

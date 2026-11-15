# Granary is an unofficial fork derived from MinIO.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Build entry policy controls with fake compilers; no server compilation."""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
PREFIX = "github.com/relvo-labs/granary/cmd."
STUB = r'''
import json, os, pathlib, subprocess, sys
args = sys.argv[1:]
with open(os.environ['BUILD_TEST_CALLS'], 'a') as log:
    log.write(json.dumps(args) + '\n')
if pathlib.Path(sys.argv[0]).name == 'docker':
    sys.exit('unexpected Docker call: ' + repr(args))
version = os.environ.get('BUILD_TEST_VERSION', 'go1.27.4')
if args[0] == 'env':
    print({'GOVERSION': version, 'GOPATH': os.environ['BUILD_TEST_ROOT'],
           'GOOS': 'linux', 'GOARCH': 'amd64'}[args[1]])
elif args[0] == 'version':
    print('go version ' + version + ' linux/amd64')
elif args[0] == 'run':
    mode = os.environ.get('BUILD_TEST_STAMP', 'valid')
    if mode == 'real':
        sys.exit(subprocess.run([os.environ['BUILD_TEST_REAL_GO'], 'run',
                 os.environ['BUILD_TEST_GENERATOR'], '2026-11-14T10:04:42Z',
                 '0123456789abcdef0123456789abcdef01234567']).returncode)
    for name, value in [('Version', '2026-11-14T10:04:42Z'),
                        ('CommitID', '0123456789abcdef0123456789abcdef01234567'),
                        ('ReleaseTag', 'DEVELOPMENT.2026-11-14T10-04-42Z')]:
        if mode == 'missing-' + name or mode == 'empty': continue
        if mode == 'blank-' + name: value = ''
        print('-X github.com/relvo-labs/granary/cmd.' + name + '=' + value, end=' ')
    sys.exit(17 if mode == 'error-with-output' else 0)
elif args[0] == 'build':
    if '-C' in args and os.environ.get('BUILD_TEST_FAIL_FIRST') == '1':
        if pathlib.Path(args[args.index('-C') + 1]).name == 'hash-set': sys.exit(23)
else:
    sys.exit('unexpected go call: ' + repr(args))
'''


class BuildEntries(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = pathlib.Path(self.scratch.name)
        for name in ('Makefile', 'go.mod', 'buildscripts/ci/tools.env',
                     'buildscripts/cross-compile.sh',
                     'buildscripts/checkdeps.sh', 'docs/debugging/build.sh'):
            dest = self.root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dest)
        self.targets = sorted(p.name for p in (ROOT / 'docs/debugging').iterdir() if p.is_dir())
        for name in self.targets:
            (self.root / 'docs/debugging' / name).mkdir()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        go = self.bin / 'go'
        go.write_text('#!' + sys.executable + '\n' + STUB)
        go.chmod(0o755)
        shutil.copyfile(go, self.bin / 'docker')
        (self.bin / 'docker').chmod(0o755)
        self.calls = self.root / 'calls.jsonl'
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        BUILD_TEST_CALLS=str(self.calls), BUILD_TEST_ROOT=str(self.root),
                        BUILD_TEST_REAL_GO=shutil.which('go'),
                        BUILD_TEST_GENERATOR=str(ROOT / 'buildscripts/gen-ldflags.go'),
                        MINIO_RELEASE='', MINIO_HOTFIX='')
        # These tests must not inherit an outer make's jobserver or overrides.
        for key in ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL'):
            self.env.pop(key, None)

    def run_entry(self, *args, **env):
        self.calls.unlink(missing_ok=True)
        result = subprocess.run(args, cwd=self.root, env=dict(self.env, **env),
                                capture_output=True, text=True, timeout=300)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        return result, calls

    def assert_no_compile(self, calls):
        self.assertFalse(any(args[0] == 'build' for args in calls), calls)

    def test_invalid_release_fails_before_any_compile(self):
        result, calls = self.run_entry('make', '-j4', 'build',
                                      MINIO_RELEASE='bad release', BUILD_TEST_STAMP='real')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('MINIO_RELEASE', result.stderr)
        self.assert_no_compile(calls)

    def test_stamp_status_and_essential_flags_gate_all_consumers(self):
        modes = ['empty', 'error-with-output']
        modes += [kind + name for kind in ('missing-', 'blank-')
                  for name in ('Version', 'CommitID', 'ReleaseTag')]
        for target in ('build', 'install-race', 'docker'):
            for mode in modes:
                with self.subTest(target=target, mode=mode):
                    result, calls = self.run_entry('make', '-j4', target, BUILD_TEST_STAMP=mode)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('version stamping', result.stderr)
                    self.assert_no_compile(calls)

    def test_default_build_generates_once_and_preserves_helper_inventory(self):
        result, calls = self.run_entry('make', '-j4', 'build')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sum(args[0] == 'run' for args in calls), 1)
        helpers = [pathlib.Path(args[args.index('-C') + 1]).name
                   for args in calls if args[0] == 'build' and '-C' in args]
        self.assertEqual(helpers, self.targets)
        server = [args for args in calls if args[0] == 'build' and '-C' not in args]
        self.assertEqual(len(server), 1)
        self.assertIn(PREFIX + 'CommitID=', ' '.join(server[0]))

    def test_patched_compiler_policy_at_direct_and_make_entries(self):
        versions = {'go1.26.10': False, 'go1.27.3': False, 'go1.26.11': True,
                    'go1.27.4': True, 'go1.28.0': True, 'go1.26.12': True,
                    'go1.27.5': True, 'go1.25.9': False, 'go1.27rc1': False,
                    'devel go1.28': False, 'garbage': False}
        for version, allowed in versions.items():
            for entry in (('bash', 'buildscripts/checkdeps.sh'),
                          ('make', '-j4', 'build'), ('make', 'build-debugging')):
                with self.subTest(version=version, entry=entry):
                    result, calls = self.run_entry(*entry, BUILD_TEST_VERSION=version)
                    self.assertEqual(result.returncode == 0, allowed, result.stdout + result.stderr)
                    if not allowed:
                        self.assertIn('GO-2026-6859', result.stdout + result.stderr)
                        self.assert_no_compile(calls)
                        self.assertFalse(any(args[0] == 'run' for args in calls), calls)

    def test_crosscompile_rejects_unpatched_before_script(self):
        result, calls = self.run_entry('make', 'crosscompile', BUILD_TEST_VERSION='go1.27.3')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('GO-2026-6859', result.stdout + result.stderr)
        self.assert_no_compile(calls)

    def test_debugging_failing_first_passing_last(self):
        result, calls = self.run_entry('bash', 'docs/debugging/build.sh', BUILD_TEST_FAIL_FIRST='1')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls[0][:3], ['build', '-C', 'docs/debugging/hash-set/'])

    def test_debugging_success_inventory(self):
        result, calls = self.run_entry('bash', 'docs/debugging/build.sh')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([pathlib.Path(args[2]).name for args in calls], self.targets)

    def test_debugging_toolchains_follow_root(self):
        toolchain = next(line for line in (ROOT / 'go.mod').read_text().splitlines()
                         if line.startswith('toolchain '))
        modules = list((ROOT / 'docs/debugging').glob('*/go.mod'))
        self.assertEqual(len(modules), 5)
        for module in modules:
            with self.subTest(module=module):
                self.assertIn(toolchain, module.read_text().splitlines())


if __name__ == '__main__':
    unittest.main()

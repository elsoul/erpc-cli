#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real inert Git objects and fake build commands; no upstream build script executes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import native_build as build


class BuildInputs(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.work = Path(self.temporary.name)
        self.source = self.work / 'source'
        self.source.mkdir()
        self.env = build.build_environment(self.work, self.work / 'compiler', False)
        self.env.update(GIT_AUTHOR_NAME='Fixture', GIT_COMMITTER_NAME='Fixture',
                        GIT_AUTHOR_EMAIL='fixture@example.invalid', GIT_COMMITTER_EMAIL='fixture@example.invalid')
        self.call(['init', '--quiet'])
        self.lock = b'version = 4\n[[package]]\nname = "fixture"\nversion = "0.0.0"\n'
        (self.source / 'Cargo.lock').write_bytes(self.lock)
        (self.source / 'rust-toolchain.toml').write_text('[toolchain]\nchannel = "1.97.1"\n')
        (self.source / 'source.rs').write_text('// inert public source fixture\n')
        self.commit()
        self.profile = {'commit': self.call(['rev-parse', 'HEAD']).decode().strip(),
                        'cargo_lock_sha256': hashlib.sha256(self.lock).hexdigest(), 'rust': '1.97.1'}
        self.catalog = {'git_sources': []}

    def tearDown(self):
        self.temporary.cleanup()

    def call(self, args):
        result = subprocess.run(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', *args],
                                cwd=self.source, env=self.env, capture_output=True, check=True)
        return result.stdout

    def commit(self):
        self.call(['add', '.'])
        self.call(['commit', '--quiet', '-m', 'inert fixture'])

    def qualify(self):
        return build.qualify_source(self.catalog, self.profile, self.source, self.env)

    @unittest.skipUnless(sys.version_info >= (3, 11), "native host uses Python3.12 tomllib")
    def test_actual_git_tree_is_verified_even_when_working_tree_cache_hides_changes(self):
        self.qualify()
        self.call(['update-index', '--assume-unchanged', 'source.rs'])
        (self.source / 'source.rs').write_text('// altered source behind assume-unchanged\n')
        self.assertEqual(self.call(['diff', 'HEAD']), b'')
        with self.assertRaises(ValueError):
            self.qualify()

    @unittest.skipUnless(sys.version_info >= (3, 11), "native host uses Python3.12 tomllib")
    def test_wrong_commit_lock_compiler_and_escaping_source_link_are_refused(self):
        self.profile['commit'] = '0' * 40
        with self.assertRaises(ValueError): self.qualify()
        self.profile['commit'] = self.call(['rev-parse', 'HEAD']).decode().strip()
        self.profile['cargo_lock_sha256'] = '0' * 64
        with self.assertRaises(ValueError): self.qualify()
        self.profile['cargo_lock_sha256'] = hashlib.sha256(self.lock).hexdigest()
        self.profile['rust'] = '1.98.1'
        with self.assertRaises(ValueError): self.qualify()
        self.profile['rust'] = '1.97.1'
        (self.source / 'escape').symlink_to('../outside')
        self.commit()
        self.profile['commit'] = self.call(['rev-parse', 'HEAD']).decode().strip()
        with self.assertRaises(ValueError): self.qualify()

    @unittest.skipUnless(sys.version_info >= (3, 11), "native host uses Python3.12 tomllib")
    def test_unreviewed_registry_or_git_sources_are_not_fetched(self):
        lock = self.lock + b'source = "unqualified-registry"\n'
        (self.source / 'Cargo.lock').write_bytes(lock)
        self.commit()
        self.profile.update(commit=self.call(['rev-parse', 'HEAD']).decode().strip(),
                            cargo_lock_sha256=hashlib.sha256(lock).hexdigest())
        with self.assertRaises(ValueError): self.qualify()

    @unittest.skipUnless(sys.version_info >= (3, 11), "native host uses Python3.12 tomllib")
    def test_effective_cargo_configs_and_untracked_includes_are_refused(self):
        config = self.source / '.cargo/config.toml'; config.parent.mkdir()
        config.write_text('[build]\njobs = 2\n')
        (self.source / '.gitignore').write_text('*.inc\n/target\n')
        self.commit(); self.profile['commit'] = self.call(['rev-parse', 'HEAD']).decode().strip()
        self.qualify()
        locations = [self.source / '.cargo/config', self.work / '.cargo/config',
                     self.work / '.cargo/config.toml', self.work / 'cargo-home/config',
                     self.work / 'cargo-home/config.toml', self.source / 'ignored.inc',
                     self.source / 'extra/build.rs']
        for path in locations:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_text('[build]\nrustc-wrapper = "/inert/unqualified-wrapper"\n')
            with self.subTest(path=str(path)), self.assertRaises(ValueError): self.qualify()
            path.unlink()
        # Cargo's ordinary output/cache can be reused; a symlink to an unrelated
        # directory cannot stand in for that output or the per-job Cargo home.
        target = self.source / 'target'; target.mkdir()
        (target / 'inert-output').write_bytes(b'no executable')
        (self.work / 'cargo-home/registry').mkdir()
        self.qualify()
        (target / 'inert-output').unlink(); target.rmdir(); target.symlink_to(self.work)
        with self.assertRaises(ValueError): self.qualify()
        target.unlink()
        (self.work / '.cargo/config.toml').symlink_to(config)
        with self.assertRaises(ValueError): self.qualify()

    @unittest.skipUnless(sys.version_info >= (3, 11), "native host uses Python3.12 tomllib")
    def test_git_worktree_override_cannot_hide_an_untracked_source_input(self):
        elsewhere = self.work / 'elsewhere'; elsewhere.mkdir()
        self.call(['config', 'core.worktree', str(elsewhere)])
        (self.source / 'injected.inc').write_text('inert unapproved include')
        self.assertEqual(self.call(['ls-files', '--others']), b'')
        with self.assertRaises(ValueError): self.qualify()

    def test_clean_environment_does_not_inherit_agent_credentials_or_compiler_overrides(self):
        with patch.dict(os.environ, {'SSH_AUTH_SOCK':'inert-private-agent','OP_SERVICE_ACCOUNT_TOKEN':'inert-private-token',
                                     'RUSTC_WRAPPER':'inert-wrapper','CARGO_HOME':'inert-user-cargo-home'}):
            env = build.build_environment(self.work, self.work / 'compiler', True)
        self.assertFalse(any('inert-private' in value for value in env.values()))
        self.assertNotIn('SSH_AUTH_SOCK', env)
        self.assertNotIn('RUSTC_WRAPPER', env)
        self.assertEqual(env['CARGO_NET_OFFLINE'], 'true')
        self.assertEqual(env['NO_RUSTUP_OVERRIDE'], '1')
        self.assertEqual(env['GIT_NO_REPLACE_OBJECTS'], '1')

    def test_scripts_wrong_architecture_links_and_changed_candidate_size_are_refused(self):
        candidate = self.work / 'candidate'
        candidate.write_bytes(b'#!/bin/sh\n' + bytes(64))
        with self.assertRaises(ValueError): build.elf(candidate, os.geteuid())
        header = bytearray(64); header[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HH', header, 16, 3, 62)
        candidate.write_bytes(header)
        self.assertEqual(build.elf(candidate, os.geteuid())['size'], 64)
        struct.pack_into('<H', header, 18, 183)
        candidate.write_bytes(header)
        with self.assertRaises(ValueError): build.elf(candidate, os.geteuid())
        alias = self.work / 'alias'; os.link(candidate, alias)
        with self.assertRaises(ValueError): build.elf(candidate, os.geteuid())


if __name__ == '__main__':
    unittest.main()

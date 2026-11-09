#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert archives and filesystem failures; no compiler or blockchain executable runs."""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import native_files as files
import native_toolchain as compiler

TOP = 'cargo-1.97.1-x86_64-unknown-linux-gnu'


def archive(path, members):
    with tarfile.open(path, 'w:xz') as tar:
        for name, kind, content in members:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.mode = 0o755 if kind == tarfile.DIRTYPE or '/bin/' in name or '/libexec/' in name or name.endswith('/install.sh') else 0o644
            if kind == tarfile.REGTYPE:
                member.size = len(content)
                tar.addfile(member, io.BytesIO(content))
            else:
                member.linkname = content.decode()
                tar.addfile(member)


class ToolchainFiles(unittest.TestCase):
    def test_fifo_receipts_and_candidates_refuse_without_blocking_file_open(self):
        helper = str(Path(__file__).resolve().parents[1] / 'templates/node')
        program = """import os,sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,sys.argv[1])
import native_files as files
import native_publish as publish
path=Path(sys.argv[2]);mode=sys.argv[3]
try:
    if mode=='read':files.read(path,owner=os.getuid())
    elif mode=='digest':files.digest_file(path,1024)
    else:publish.copy_binary(path,path.with_name('destination'),{'size':64,'sha256':'a'*64},os.getuid())
except files.Refused:raise SystemExit(3)
raise SystemExit(4)
"""
        with tempfile.TemporaryDirectory() as temporary:
            fifo=Path(temporary)/'receipt';os.mkfifo(fifo)
            for mode in ('read','digest','candidate'):
                result=subprocess.run([sys.executable,'-I','-c',program,helper,str(fifo),mode],capture_output=True,timeout=10)
                self.assertEqual(result.returncode,3,(mode,result.stderr.decode()))
            self.assertFalse(fifo.with_name('destination').exists())

    def test_component_layout_is_published_readonly_without_executing_install_script(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload, tar = root / 'payload', root / 'component.tar.xz'
            payload.mkdir()
            archive(tar, [(TOP + '/install.sh', tarfile.REGTYPE, b'not an executable fixture'),
                          (TOP + '/cargo/manifest.in', tarfile.REGTYPE, b'file:bin/cargo\n'),
                          (TOP + '/cargo/bin/cargo', tarfile.REGTYPE, b'inert compiler placeholder')])
            old = os.umask(0o077)
            try:
                receipt = compiler.extract(tar, 'cargo', '1.97.1', payload)
                compiler.seal_directories(payload)
                files.atomic(payload / 'receipt.json', b'inert private receipt')
            finally:
                os.umask(old)
            self.assertEqual(set(receipt), {'bin/cargo'})
            self.assertFalse((payload / 'install.sh').exists())
            self.assertFalse((payload / 'manifest.in').exists())
            self.assertEqual(stat.S_IMODE((payload / 'bin').stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE((payload / 'bin/cargo').stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE((payload / 'receipt.json').stat().st_mode), 0o600)
            self.assertEqual(receipt['bin/cargo']['sha256'], hashlib.sha256(b'inert compiler placeholder').hexdigest())

    def test_all_six_qualified_archive_member_lists_extract_with_public_permissions(self):
        fixtures = json.loads((Path(__file__).parent / 'compiler-members.json').read_text())
        catalog = json.loads((Path(__file__).resolve().parents[1] / 'templates/node/catalog.json').read_text())
        for profile in catalog['networks'].values():
            version = profile['rust']
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); payload = root / 'payload'; payload.mkdir()
                published = {}
                for component, pin in profile['components'].items():
                    fixture = fixtures[version][component]
                    self.assertEqual(fixture['sha256'], pin['sha256'])
                    tar = root / (component + '.tar.xz')
                    # The fixture records every actual regular member name of
                    # the hash-qualified stream. Payloads here are tiny inert
                    # text; no real installer/compiler/library is extracted.
                    members = [(name, tarfile.REGTYPE, b'inert member') for name in fixture['files']]
                    archive(tar, members)
                    old = os.umask(0o077)
                    try:
                        result = compiler.extract(tar, component, version, payload)
                    finally:
                        os.umask(old)
                    self.assertFalse(set(published).intersection(result))
                    published.update(result)
                    prefix = component + '-' + version + '-' + compiler.TARGET + '/'
                    inner = component if component != 'rust-std' else 'rust-std-' + compiler.TARGET
                    expected = {name[len(prefix + inner + '/'):]
                                for name in fixture['files'] if name.startswith(prefix + inner + '/')}
                    expected.discard('manifest.in')
                    self.assertEqual(set(result), expected)
                compiler.seal_directories(payload)
                for name in ('bin/rustc', 'bin/cargo', 'bin/rustdoc', 'libexec/rust-analyzer-proc-macro-srv'):
                    self.assertIn(name, published)
                    self.assertEqual(stat.S_IMODE((payload / name).stat().st_mode), 0o555)
                self.assertEqual(stat.S_IMODE((payload / 'libexec').stat().st_mode), 0o755)
                self.assertEqual(stat.S_IMODE((payload / 'share/man/man1/cargo.1').stat().st_mode), 0o444)
                self.assertFalse((payload / 'install.sh').exists())

    def test_links_path_escapes_duplicates_and_other_components_are_refused(self):
        bad = [('/etc/fixture', tarfile.REGTYPE, b'x'),
               (TOP + '/cargo/../../escape', tarfile.REGTYPE, b'x'),
               (TOP + '/cargo/bin/cargo', tarfile.SYMTYPE, b'/etc/fixture'),
               (TOP + '/cargo/bin/cargo', tarfile.LNKTYPE, b'outside'),
               ('other/cargo/bin/cargo', tarfile.REGTYPE, b'x'),
               (TOP + '/cargo/unexpected/file', tarfile.REGTYPE, b'x')]
        for member in bad:
            with self.subTest(member=member[0]), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); payload = root / 'payload'; payload.mkdir()
                tar = root / 'component.tar.xz'; archive(tar, [member])
                with self.assertRaises(ValueError):
                    compiler.extract(tar, 'cargo', '1.97.1', payload)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); payload = root / 'payload'; payload.mkdir()
            tar = root / 'component.tar.xz'; member = (TOP + '/cargo/bin/cargo', tarfile.REGTYPE, b'x')
            archive(tar, [member, member])
            with self.assertRaises(ValueError):
                compiler.extract(tar, 'cargo', '1.97.1', payload)

    def test_atomic_replaces_old_open_descriptors_and_fsyncs_file_then_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'state'
            files.atomic(path, b'old')
            old = os.open(path, os.O_WRONLY)
            order, original = [], os.fsync
            def sync(fd):
                order.append('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file')
                original(fd)
            with patch.object(os, 'fsync', sync):
                files.atomic(path, b'new', 0o644)
            os.write(old, b'corrupt'); os.close(old)
            self.assertEqual(path.read_bytes(), b'new')
            self.assertEqual(order, ['file', 'directory'])
            with patch.object(files, 'sync_directory', side_effect=OSError('inert durability failure')):
                with self.assertRaises(OSError):
                    files.atomic(path, b'pending')

    def test_duplicate_json_and_nonregular_or_hardlinked_artifacts_are_rejected(self):
        with self.assertRaises(ValueError):
            files.json_value(b'{"intent":1,"intent":2}')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); original = root / 'original'; original.write_bytes(b'public')
            os.link(original, root / 'alias')
            with self.assertRaises(ValueError):
                files.digest_file(original, 20)
            (root / 'alias').unlink()
            (root / 'link').symlink_to(original)
            with self.assertRaises(OSError):
                files.digest_file(root / 'link', 20)
            with self.assertRaises(ValueError):
                files.digest_file(original, 2)

    def test_download_does_not_trust_http_status_encoding_origin_or_an_unmatched_digest(self):
        class Response(io.BytesIO):
            status = 200
            headers = {}
            def geturl(self): return pin['url']
        catalog = json.loads((Path(__file__).resolve().parents[1] / 'templates/node/catalog.json').read_text())
        pin = {'url': catalog['networks']['mainnet']['components']['cargo']['url'],
               'maximum_bytes': 8, 'size': 7, 'sha256': hashlib.sha256(b'fixture').hexdigest()}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for kind in ('good', 'digest', 'size', 'oversize', 'status', 'encoding'):
                response = Response(b'oversized fixture' if kind == 'oversize' else b'fixture')
                if kind == 'status': response.status = 302
                if kind == 'encoding': response.headers = {'Content-Encoding': 'gzip'}
                selected = dict(pin, sha256='0' * 64) if kind == 'digest' else pin
                if kind == 'size': selected = dict(pin, size=6)
                opener = types.SimpleNamespace(open=lambda *_, **__: response)
                with patch.object(compiler.urllib.request, 'build_opener', return_value=opener):
                    if kind == 'good': compiler.download(selected, root / kind)
                    else:
                        with self.assertRaises(ValueError): compiler.download(selected, root / kind)
            for origin in (pin['url'].replace('https:', 'http:'),
                           pin['url'].replace('static.rust-lang.org', 'github.com@static.rust-lang.org')):
                with patch.object(compiler.urllib.request, 'build_opener') as opener:
                    with self.assertRaises(ValueError): compiler.download(dict(pin, url=origin), root / 'bad')
                    opener.assert_not_called()


if __name__ == '__main__':
    unittest.main()

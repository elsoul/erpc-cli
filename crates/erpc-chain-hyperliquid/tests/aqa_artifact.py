# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert signed-artifact boundaries; no publisher executable is run."""
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parents[1]/'templates/aqa'))
import erpc_aqa_artifact as artifact
import erpc_aqa_common as common


class Artifact(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        self.catalog=json.loads((Path(__file__).parents[1]/'templates/aqa/catalog.json').read_bytes())
        self.binary=b'\x7fELF\x02\x01'+bytes(12)+b'\x3e\x00'+b'inert-not-executable'
        self.catalog['artifact'].update(binary_size=len(self.binary),binary_sha256=common.digest(self.binary))
        self.patches=[]
        def install(obj,name,value):
            p=patch.object(obj,name,value);p.start();self.patches.append(p)
        self.addCleanup(lambda:[p.stop() for p in reversed(self.patches)])
        real=Path.lstat
        def info(path,*a,**kw):
            value=list(real(path,*a,**kw));value[4]=0;return os.stat_result(value)
        install(Path,'lstat',info)
        install(artifact,'read',lambda path,limit=1048576:common.read(path,limit,os.getuid()))
        def directory(path,create=False,mode=0o755):
            if create:path.mkdir(parents=True,mode=mode,exist_ok=True)
            if path.is_symlink() or not path.is_dir() or path.stat().st_mode&0o022:raise ValueError('inert unsafe namespace')
        install(artifact,'owned_directory',directory);install(artifact,'RELEASES',self.root/'releases')
        self.archive=self.make_archive()
        install(artifact,'download',lambda pin,path:path.write_bytes(self.archive))
        self.calls=[]
        def execute(args):
            self.calls.append(args)
            return types.SimpleNamespace(stdout=('[GNUPG:] VALIDSIG '+self.catalog['artifact']['signer']+' 2026-03-31 '+str(self.catalog['artifact']['signed_at'])+'\n').encode())
        install(artifact,'execute',execute)

    def make_archive(self,extra=None):
        buffer=io.BytesIO()
        with tarfile.open(fileobj=buffer,mode='w:gz') as archive:
            for name,data in [('publish_daemon',self.binary),('._publish_daemon',bytes(163))]:
                member=tarfile.TarInfo(name);member.size=len(data);archive.addfile(member,io.BytesIO(data))
            if extra is not None:archive.addfile(extra)
        return buffer.getvalue()

    def test_install_checks_signature_binary_bytes_modes_and_retry_durability(self):
        old=os.umask(0o077)
        try:artifact.install(self.catalog)
        finally:os.umask(old)
        binary=artifact.check(self.catalog)
        self.assertEqual(binary.read_bytes(),self.binary);self.assertEqual(binary.stat().st_mode&0o777,0o555)
        self.assertEqual(binary.parent.stat().st_mode&0o777,0o755)
        self.assertEqual(self.calls[0][0],'/usr/bin/gpgv')
        self.assertFalse(any('publish_daemon'==str(a) for a in self.calls[0]))
        inode=binary.stat().st_ino
        with patch.object(artifact,'fsync_dir',side_effect=OSError('inert storage failure')):
            with self.assertRaises(OSError):artifact.install(self.catalog)
        artifact.install(self.catalog);self.assertEqual(binary.stat().st_ino,inode)

    def test_archive_unknown_paths_links_duplicate_and_changed_bytes_refuse(self):
        artifact.RELEASES.mkdir()
        for index,name in enumerate(('../outside','/tmp/outside','unknown','publish_daemon')):
            directory=self.root/str(index);directory.mkdir()
            member=tarfile.TarInfo(name);member.type=tarfile.SYMTYPE;member.linkname='/tmp/outside'
            (directory/'archive.tar.gz').write_bytes(self.make_archive(member))
            with self.assertRaises(ValueError):artifact.unpack(self.catalog,directory)
        directory=self.root/'wrong';directory.mkdir();(directory/'archive.tar.gz').write_bytes(self.archive)
        self.catalog['artifact']['binary_sha256']='0'*64
        with self.assertRaises(ValueError):artifact.unpack(self.catalog,directory)

    def test_bad_signer_missing_receipt_or_unsafe_final_executable_refuses(self):
        with patch.object(artifact,'execute',return_value=types.SimpleNamespace(stdout=b'[GNUPG:] VALIDSIG foreign\n')):
            with self.assertRaises(ValueError):artifact.install(self.catalog)
        artifact.install(self.catalog);binary=artifact.check(self.catalog)
        binary.chmod(0o755)
        with self.assertRaises(ValueError):artifact.check(self.catalog)
        binary.chmod(0o555);binary.unlink();binary.symlink_to(self.root/'foreign')
        with self.assertRaises(ValueError):artifact.check(self.catalog)

    def test_redirect_origins_cannot_select_local_insecure_or_credentialed_urls(self):
        artifact.origin('https://github.com/native-markets/aqa-publisher/releases/download/v1.2.0/file')
        for url in ('http://127.0.0.1/file','https://127.0.0.1/file','https://bitcoincore.org/file',
                    'https://user:password@github.com/file','https://github.com:444/file'):
            with self.assertRaises(ValueError):artifact.origin(url)


if __name__=='__main__':unittest.main()

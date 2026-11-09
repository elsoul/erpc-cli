# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert proc metadata: old privileged login descendants are not quiescent."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'templates/node'))
import native_migration_retire as migration


class OriginalProcesses(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        item=patch.object(migration.process,'PROC',self.root);item.start();self.addCleanup(item.stop)
    def process(self,pid,uid,login):
        path=self.root/str(pid);path.mkdir()
        (path/'stat').write_bytes((str(pid)+' (inert) S '+'0 '*18+'12345\n').encode())
        (path/'status').write_bytes(('Uid:\t'+('\t'.join([str(uid)]*4))+'\n').encode())
        (path/'loginuid').write_bytes(str(login).encode());return path
    def test_only_original_proven_main_may_exist_before_stop(self):
        main=self.process(100,1001,4294967295);self.process(200,0,2002)
        migration.original_processes(1001,100)
        with self.assertRaises(ValueError):migration.original_quiescent(1001)
        for path in main.iterdir():path.unlink()
        main.rmdir();migration.original_quiescent(1001)
    def test_privileged_old_login_descendant_is_refused_even_without_old_effective_uid(self):
        self.process(100,0,1001)
        with self.assertRaises(ValueError):migration.original_quiescent(1001)
        with self.assertRaises(ValueError):migration.original_processes(1001,100)
    def test_missing_unreadable_or_malformed_audit_metadata_never_implies_quiescence(self):
        path=self.process(100,0,4294967295);(path/'loginuid').write_bytes(b'unknown')
        with self.assertRaises(ValueError):migration.original_quiescent(1001)
        (path/'loginuid').unlink()
        with self.assertRaises(ValueError):migration.original_quiescent(1001)
        (path/'loginuid').write_bytes(b'4294967295')
        real=migration.process.bounded
        def unavailable(file,maximum):
            if file.name=='loginuid':raise PermissionError('inert protected proc metadata')
            return real(file,maximum)
        with patch.object(migration.process,'bounded',unavailable),self.assertRaises(PermissionError):migration.original_quiescent(1001)
    def test_generation_change_between_uid_and_audit_reads_is_not_adopted(self):
        self.process(100,0,4294967295)
        with patch.object(migration.process,'generation',side_effect=[1,2]),self.assertRaises(ValueError):migration.original_quiescent(1001)

if __name__=='__main__':unittest.main()

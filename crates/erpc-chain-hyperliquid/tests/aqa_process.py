# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert kernel-shaped process metadata and pidfd decisions; no process is signaled."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parents[1]/'templates/aqa'))
import erpc_aqa_process as p


class Processes(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.proc=self.root/'proc';self.proc.mkdir()
        self.entry=self.proc/'123';self.entry.mkdir();self.image=self.root/'publish_daemon'
        self.image.write_bytes(b'inert not-executable publisher image')
        self.account={'uid':995,'gid':995}
        self.approved={str(self.image):{'argv':[str(self.image)],'sha256':hashlib.sha256(self.image.read_bytes()).hexdigest()}}
        self.original={
            'stat':'123 (publisher (inert)) '+' '.join(['S']+['0']*18+['99']),
            'status':'Uid:\t995\t995\t995\t995\nGid:\t995\t995\t995\t995\nGroups:\t995\n',
            'cgroup':'0::/system.slice/'+p.UNIT+'\n',
        }
        for name,value in self.original.items():(self.entry/name).write_text(value)
        (self.entry/'cmdline').write_bytes(str(self.image).encode()+b'\0')
        (self.entry/'exe').symlink_to(self.image)
        fixture=patch.object(p,'PROC',self.proc);fixture.start();self.addCleanup(fixture.stop)

    def test_exact_kernel_identity_image_argv_and_generation_are_required(self):
        self.assertEqual(p.prove(123,self.account,self.approved),'99')
        self.assertEqual(p.scan(self.account,self.approved),({123:'99'},False))
        mutations={'status':self.original['status'].replace('Groups:\t995','Groups:\t995 27'),
                   'cgroup':'0::/user.slice\n','cmdline':'/inert/other\0'}
        for name,value in mutations.items():
            path=self.entry/name;original=path.read_bytes();path.write_text(value)
            with self.subTest(name=name),self.assertRaises(ValueError):p.prove(123,self.account,self.approved)
            self.assertEqual(p.scan(self.account,self.approved),({},True));path.write_bytes(original)
        self.image.write_bytes(b'substituted image')
        with self.assertRaises(ValueError):p.prove(123,self.account,self.approved)

    def test_foreign_uid_is_never_claimed_and_zombies_are_not_writers(self):
        (self.entry/'status').write_text(self.original['status'].replace('995','996'))
        self.assertEqual(p.scan(self.account,self.approved),({},False))
        (self.entry/'status').write_text(self.original['status'])
        (self.entry/'stat').write_text(self.original['stat'].replace(') S ',') Z '))
        p.quiescent(self.account,self.approved)

    def test_failed_unit_stop_still_drains_exact_owned_pid_without_claiming_success(self):
        with patch.object(p,'scan',side_effect=[({123:'99'},False),({},False)]),\
             patch.object(p.os,'pidfd_open',return_value=7,create=True),\
             patch.object(p.signal,'pidfd_send_signal',create=True) as signal,patch.object(p.os,'close'),\
             self.assertRaises(ValueError):
            p.stop(self.account,self.approved,lambda:(_ for _ in ()).throw(OSError('inert missing unit')))
        signal.assert_called_once_with(7,p.signal.SIGTERM)

    def test_missing_unit_orphan_is_drained_and_reused_pid_is_never_signaled(self):
        for generation in ('99','100'):
            with patch.object(p,'scan',side_effect=[({123:'99'},False),({},False)]),\
                 patch.object(p,'prove',return_value=generation),\
                 patch.object(p.os,'pidfd_open',return_value=7,create=True),\
                 patch.object(p.signal,'pidfd_send_signal',create=True) as signal,patch.object(p.os,'close'):
                if generation=='99':p.stop(self.account,self.approved,lambda:None)
                else:
                    with self.assertRaises(ValueError):p.stop(self.account,self.approved,lambda:None)
                self.assertEqual(signal.call_count,int(generation=='99'))

    def test_unknown_writer_never_authorizes_start_or_foreign_signal(self):
        (self.entry/'cgroup').write_text('0::/foreign.slice\n')
        with self.assertRaises(ValueError):p.quiescent(self.account,self.approved)
        with patch.object(p.os,'pidfd_open',create=True) as descriptor,self.assertRaises(ValueError):
            p.stop(self.account,self.approved,lambda:None)
        descriptor.assert_not_called()


if __name__=='__main__':unittest.main()

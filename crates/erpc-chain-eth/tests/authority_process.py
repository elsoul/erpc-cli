# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Kernel-shaped public process fixtures; no actual signals or native programs."""
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parents[1]/'templates/authority'))
import eth_process as process


class Process(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.addCleanup(patch.stopall)
        self.root=Path(temp.name);self.proc=self.root/'proc';self.proc.mkdir()
        patch.object(process,'PROC',self.proc).start()
        self.account={'uid':991,'gid':990};self.plan={'users':{'reth':self.account}}
        self.image=self.root/'reth';self.image.write_bytes(b'inert native image')
        self.args=[str(self.image),'node','--chain','mainnet']
        self.approved={str(self.image):[dict(self.account,unit='reth.service',argv=self.args,sha256=hashlib.sha256(self.image.read_bytes()).hexdigest())]}
        self.signals=[]
        patch.object(process.os,'pidfd_open',side_effect=lambda _pid:os.open(os.devnull,os.O_RDONLY),create=True).start()
        def signal(_fd,_signal):self.signals.append(_signal);shutil.rmtree(self.proc/'123')
        patch.object(process.signal,'pidfd_send_signal',side_effect=signal,create=True).start()

    def record(self,pid=123,uid=991,group=990,state='S',generation=99):
        directory=self.proc/str(pid);directory.mkdir(exist_ok=True)
        (directory/'stat').write_text(f'{pid} (inert native) {state} '+'0 '*18+f'{generation} 0\n')
        (directory/'status').write_text(f'Uid:\t{uid} {uid} {uid} {uid}\nGid:\t{group} {group} {group} {group}\nGroups:\t{group}\n'+
            'CapInh:\t00000000\nCapPrm:\t00000000\nCapEff:\t00000000\nCapAmb:\t00000000\nNoNewPrivs:\t1\n')
        (directory/'cmdline').write_bytes(b'\0'.join(arg.encode() for arg in self.args)+b'\0')
        (directory/'cgroup').write_text('0::/system.slice/reth.service\n')
        if not (directory/'exe').is_symlink():(directory/'exe').symlink_to(self.image)
        return directory

    def test_retained_original_image_argv_cgroup_and_generation_are_required(self):
        directory=self.record();self.assertEqual(process.prove(123,self.account,self.approved),99)
        with self.assertRaises(ValueError):process.prove(123,self.account,self.approved,unit='lighthouse.service')
        for name,bad in [('cmdline',b'/inert/other\0'),('cgroup',b'0::/foreign.slice/reth.service\n')]:
            path=directory/name;original=path.read_bytes();path.write_bytes(bad)
            found,unknown=process.scan(self.plan,self.approved);self.assertEqual(found,{});self.assertTrue(unknown)
            path.write_bytes(original)
        path=directory/'status';path.write_text(path.read_text().replace('CapEff:\t00000000','CapEff:\t00000001'))
        with self.assertRaises(ValueError):process.prove(123,self.account,self.approved)

    def test_missing_service_or_failed_stop_does_not_skip_the_original_orphan_writer(self):
        self.record();calls=[]
        process.stop(self.plan,self.approved,lambda:calls.append('missing unit checked'))
        self.assertEqual(len(self.signals),1);self.assertEqual(calls,['missing unit checked']);process.quiescent(self.plan,self.approved)
        self.record();self.signals.clear()
        def failed():raise OSError('inert unit failure')
        with self.assertRaises(ValueError):process.stop(self.plan,self.approved,failed)
        self.assertEqual(len(self.signals),1);self.assertFalse((self.proc/'123').exists())

    def test_foreign_uid_is_not_signaled_and_unknown_original_writer_is_not_adopted(self):
        directory=self.record(uid=77);process.stop(self.plan,self.approved,lambda:None)
        self.assertEqual(self.signals,[]);self.assertTrue(directory.exists())
        shutil.rmtree(directory);self.record();self.image.write_bytes(b'inert unapproved replacement')
        with self.assertRaises(ValueError):process.stop(self.plan,self.approved,lambda:None)
        self.assertEqual(self.signals,[])

    def test_pid_reuse_after_pidfd_open_never_sends_a_signal(self):
        self.record()
        def reused(_pid):self.record(generation=100);return os.open(os.devnull,os.O_RDONLY)
        with patch.object(process.os,'pidfd_open',side_effect=reused),patch.object(process.time,'monotonic',side_effect=[0,1000]):
            with self.assertRaises(ValueError):process.stop(self.plan,self.approved,lambda:None)
        self.assertEqual(self.signals,[])


if __name__=='__main__':unittest.main()

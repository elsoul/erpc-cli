# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Volatile staging and child-death contract; native execution is entirely inert."""
import os
from pathlib import Path
import signal
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import authority_accounts as fixtures
import eth_validator_native as native


class Native(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.Accounts();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.root=self.f.root;self.mounts=self.root/'mountinfo';self.f.install(native,'MOUNTS',self.mounts)
        self.runtime=self.root/'volatile';self.runtime.mkdir()
        info=self.runtime.stat();self.device=str(os.major(info.st_dev))+':'+str(os.minor(info.st_dev))
        self.mounts.write_text('1 0 '+self.device+' / '+str(self.runtime)+' rw - tmpfs tmpfs rw\n')

    def test_only_real_volatile_filesystem_can_receive_private_staging(self):
        first=native.scratch(self.runtime);second=native.scratch(self.runtime)
        self.assertNotEqual(first,second);self.assertEqual(first.stat().st_mode&0o777,0o700)
        self.mounts.write_text('1 0 '+self.device+' / '+str(self.runtime)+' rw - ext4 /inert/device rw\n')
        with self.assertRaises(ValueError):native.scratch(self.runtime)
        self.assertEqual(len(list(self.runtime.iterdir())),2)

    def test_more_specific_mount_and_symbolic_runtime_are_not_mistaken_for_original_tmpfs(self):
        stage=native.scratch(self.runtime)
        with self.mounts.open('a') as output:output.write('2 1 '+self.device+' / '+str(stage)+' rw - ext4 /inert/device rw\n')
        with self.assertRaises(ValueError):native.volatile(stage)
        link=self.root/'redirect';link.symlink_to(self.runtime)
        with self.assertRaises((OSError,ValueError)):native.volatile(link)

    def test_child_contract_sets_no_new_privileges_parent_death_private_umask_and_core_limit(self):
        executable=self.root/'inert-native';executable.write_bytes(b'inert, never executed');executable.chmod(0o755)
        calls=[]
        class Lib:
            def prctl(self,*args):calls.append(args);return 0
        def subprocess(argv,**kwargs):
            self.assertEqual(argv,[str(executable),'public-argument']);self.assertEqual(kwargs['input'],b'inert private input')
            self.assertEqual(kwargs['umask'],0o077);self.assertTrue(kwargs['close_fds']);self.assertEqual(kwargs['env'],native.ENV)
            with patch.object(native.os,'getppid',return_value=os.getpid()),patch.object(native.resource,'setrlimit') as limit:
                kwargs['preexec_fn']();limit.assert_called_once_with(native.resource.RLIMIT_CORE,(0,0))
            return SimpleNamespace(returncode=0,stdout=b'public result',stderr=b'inert private diagnostics')
        with patch.object(native.ctypes,'CDLL',return_value=Lib()),patch.object(native.os,'getxattr',return_value=b'',create=True),\
             patch.object(native.subprocess,'run',side_effect=subprocess):
            self.assertEqual(native.worker([str(executable),'public-argument'],input_data=b'inert private input'),b'public result')
        self.assertEqual(calls,[(38,1,0,0,0),(1,signal.SIGKILL,0,0,0)])

    def test_file_capability_or_indirect_executable_is_refused_before_spawn(self):
        executable=self.root/'inert-native';executable.write_bytes(b'inert');executable.chmod(0o755)
        with patch.object(native.os,'getxattr',return_value=b'inert capabilities',create=True),patch.object(native.subprocess,'run') as spawn:
            with self.assertRaises(ValueError):native.worker([str(executable)])
            spawn.assert_not_called()
        link=self.root/'alias';link.symlink_to(executable)
        with patch.object(native.subprocess,'run') as spawn:
            with self.assertRaises(OSError):native.worker([str(link)])
            spawn.assert_not_called()


if __name__=='__main__':unittest.main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert systemd metadata and continuation checks; no unit or account is created."""
import hashlib
import json
import os
import types
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import native_build_jobs as jobs
import native_files as files
import native_process
import native_publish


class BuildJobs(unittest.TestCase):
    def test_fetch_and_compile_units_have_separate_network_authority_and_no_node_key_paths(self):
        for phase in ('fetch','compile'):
            name, unit = jobs.unit('a'*64,'b'*32,phase)
            self.assertIn('User=erpc-solana-build',unit)
            self.assertIn('ExecStart=/usr/bin/env -i ',unit)
            self.assertIn('NoNewPrivileges=true',unit)
            self.assertIn('MemorySwapMax=0',unit)
            self.assertIn('PrivateNetwork='+('false' if phase=='fetch' else 'true'),unit)
            self.assertEqual([line for line in unit.splitlines() if line.startswith('ReadWritePaths=')],
                             ['ReadWritePaths=/var/lib/erpc-solana-build/jobs/'+'b'*32+'/work'])
            for secret in ['LoadCredential','OP_SERVICE_ACCOUNT_TOKEN','SSH_AUTH_SOCK','/etc/erpc/solana']:
                self.assertNotIn(secret,unit)
            self.assertNotIn('[Install]',unit,'build jobs must not auto-start on boot')
        for bad in ('../escape','$(id)','a'*31):
            with self.assertRaises(ValueError):jobs.unit('a'*64,bad,'compile')

    def metadata(self,intent,phase,active='inactive',**changes):
        values={'LoadState':'loaded','ActiveState':active,'SubState':'dead','Result':'success','MainPID':'0',
                'ExecMainStatus':'0','FragmentPath':str(jobs.UNITS/jobs.unit_name(intent,phase)),
                'DropInPaths':'','User':'erpc-solana-build','Group':'erpc-solana-build','NeedDaemonReload':'no'}
        values.update(changes)
        return '\n'.join(key+'='+value for key,value in values.items())+'\n'

    def test_unknown_dropin_user_fragment_or_reload_never_counts_as_an_owned_job(self):
        for key,value in [('User','root'),('Group','sudo'),('DropInPaths','/etc/foreign.conf'),
                          ('FragmentPath','/usr/lib/systemd/system/other.service'),('NeedDaemonReload','yes')]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                jobs.inspect('b'*32,'fetch',lambda _:self.metadata('b'*32,'fetch',**{key:value}))
        self.assertEqual(jobs.inspect('b'*32,'compile',lambda _:self.metadata('b'*32,'compile','active',SubState='exited')),'complete')
        with self.assertRaises(ValueError):
            jobs.inspect('b'*32,'compile',lambda _:self.metadata('b'*32,'compile','active',SubState='exited',ExecMainStatus='1'))

    def test_queued_job_without_main_pid_still_blocks_another_builder(self):
        name=jobs.unit_name('b'*32,'compile')
        for active,sub in [('activating','start'),('active','exited'),('deactivating','stop')]:
            with self.subTest(active=active),self.assertRaises(ValueError):
                jobs.idle_units(lambda _:name+' loaded '+active+' '+sub+' ERPC builder\n')
        jobs.idle_units(lambda _:name+' loaded inactive dead ERPC builder\n')
        jobs.idle_units(lambda _:name+' loaded failed failed ERPC builder\n')

    def test_completed_compile_survives_interrupted_shutdown_without_authorizing_failed_build(self):
        intent,revision='b'*32,'a'*64
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/intent).mkdir();(root/revision).mkdir()
            catalog=(Path(__file__).resolve().parents[1]/'templates/node/catalog.json').read_bytes()
            (root/revision/'catalog.json').write_bytes(catalog)
            public=jobs.request(catalog,'testnet',intent)
            (root/intent/'request.json').write_bytes(files.encoded(public))
            account=types.SimpleNamespace(pw_uid=2001,pw_gid=2001,pw_shell='/usr/sbin/nologin',pw_dir='/var/lib/erpc-solana-build')
            calls=[];fail=[True]
            def run(args):
                calls.append(args)
                if args[0]=='show':
                    phase='compile' if '-compile-' in args[1] else 'fetch'
                    return self.metadata(intent,phase,'active' if fail[0] else 'inactive',SubState='exited' if fail[0] else 'dead')
                if args[0]=='stop' and fail[0]:
                    fail[0]=False
                    raise OSError('interrupted shutdown')
                return ''
            def publish_candidate(*args):
                args[-1]()
                return 'candidate only'
            with patch.object(jobs,'JOBS',root),patch.object(jobs,'UNITS',root),patch.object(jobs,'HELPERS',root),\
                 patch.object(jobs,'root_directory'),patch.object(jobs,'read',lambda path,maximum=1048576:files.read(path,maximum,os.geteuid())),\
                 patch.object(jobs.pwd,'getpwnam',return_value=account),patch.object(native_process,'assert_quiescent') as quiescent,\
                 patch.object(native_publish,'publish',side_effect=publish_candidate) as publisher:
                for phase in ('fetch','compile'):
                    name,text=jobs.unit(revision,intent,phase);(root/name).write_text(text)
                with self.assertRaises(OSError):jobs.finish(Mock(),{'network':'testnet'},intent,revision,run)
                publisher.assert_not_called()
                self.assertTrue((root/intent/'compile-completed.json').is_file())
                self.assertEqual(jobs.finish(Mock(),{'network':'testnet'},intent,revision,run),'candidate only')
                quiescent.assert_called_once_with(2001)
                (root/intent/'compile-completed.json').unlink()
                with self.assertRaises(ValueError):jobs.finish(Mock(),{'network':'testnet'},intent,revision,run)
                self.assertEqual(publisher.call_count,1,'inactive unit without durable success must not publish')

    def test_cancellation_during_preparation_cannot_submit_a_stale_build(self):
        intent,revision='b'*32,'a'*64
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); (root/intent).mkdir()
            public={'intent':intent,'network':'testnet'}
            calls=[]
            def run(args):
                calls.append(args)
                if args[0]=='show':return self.metadata(intent,'fetch')
                return ''
            state=Mock();state.current.side_effect=[{},ValueError('cancelled')]
            with patch.object(jobs,'JOBS',root),patch.object(jobs,'UNITS',root):
                name,unit=jobs.unit(revision,intent,'fetch')
                (root/name).write_text(unit);(root/intent/'request.json').write_text(json.dumps(public))
                with patch.object(jobs,'read',lambda path,maximum=0:path.read_bytes()):
                    with self.assertRaises(ValueError):
                        jobs.start(state,{'network':'testnet'},intent,'fetch',revision,lambda:None,run)
            self.assertFalse(any(call[0]=='start' for call in calls))


if __name__=='__main__':unittest.main()

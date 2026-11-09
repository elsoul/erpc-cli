# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual persistent condition rejects delayed legacy runs without killing PIDs."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'templates/node'))
import native_files as files
import native_migration_guard as guard
import native_migration_runs as runs
import native_migration_retire as retirement
from migration_retire import Coordinator
INSTALL=guard.install
IDLE=guard.other_runs_idle


class Guard(unittest.TestCase):
    def setUp(self):
        self.fixture=Coordinator('runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        f=self.fixture;self.operation=f.operation;self.operation.reserve();self.revision='e'*64
        self.directory=f.root/'etc/systemd/system/erpc-r-.service.d';self.dropin=self.directory/'90-erpc-native-owner.conf'
        f.patch(guard,'DIRECTORY',self.directory);f.patch(guard,'DROPIN',self.dropin)
        f.patch(guard,'root_directory',f.trusted)
        f.patch(guard,'read',lambda path,maximum=1048576:files.read(path,maximum,os.getuid()))
        f.patch(guard,'sync_file',lambda path:files.sync_file(path,os.getuid()))
        f.patch(guard.helpers,'verify',lambda revision:files.require(revision==self.revision,'unqualified helper'))
        f.patch(guard,'other_runs_idle',IDLE)
        f.patch(guard,'own_unit',lambda:'erpc-r-current.service')
        self.jobs='';self.units='';self.observed={};self.commands=[]
        self.current=f.root/'runs/r-current';self.current.mkdir(parents=True)
        self.late=f.root/'runs/r-delayed';self.late.mkdir()
        f.patch(retirement,'RUNS',self.current.parent)
        self.helper={'binding_sha256':hashlib.sha256(files.encoded(self.operation.binding)).hexdigest(),'revision':self.revision}
        files.atomic(f.store/'helper-revision.json',files.encoded(self.helper))
        self.operation.run=self.command
    def command(self,args):
        self.commands.append(args)
        if args[0]=='/usr/bin/busctl':return json.dumps({'type':'a(sasasttttuii)','data':[self.launch]})
        if args[1]=='list-jobs':return self.jobs
        if args[1]=='list-units':return self.units
        if args[1]=='show':return ''.join(k+'='+v+'\n' for k,v in self.observed.items())
        if args[1]=='daemon-reload':return ''
        self.fail('unidentified process or service was manipulated')
    def bundle(self,play='ansible/solana-native/migration.yml'):
        (self.late/'bundle').mkdir(exist_ok=True)
        inventory={'all':{'hosts':{self.operation.binding['contract']['name']:{'ansible_connection':'local',
            'solana_native_loader':'inert compiled loader','solana_native_request':copy.deepcopy(dict(self.operation.binding,action='migration-copy'))}}}}
        files.atomic(self.late/'bundle/inventory.yml',files.encoded(inventory))
        files.atomic(self.late/'sealed.json',files.encoded({'bundle':'a'*64,'login':1002,'group':1102}))
        self.launch=['/bin/bash',['/bin/bash',str(self.late/'node-run.sh'),str(self.late),'a'*64,play],[],0,0,0,0,0,0,0]
        return inventory
    def test_actual_persistent_condition_allows_only_same_owner_native_bundle(self):
        INSTALL(self.operation);self.assertIn(b'ExecCondition=+',self.dropin.read_bytes())
        self.assertIn(b'migration-run-condition %n',self.dropin.read_bytes())
        self.bundle();self.assertTrue(guard.permit('erpc-r-delayed.service',self.command))
        # Both existing RPC and validator play paths can replace old Solv units;
        # their late root runner is rejected before that Ansible entry executes.
        for play in ('ansible/rpc/deploy.yml','ansible/validator/deploy.yml','ansible/solana-native/../rpc/deploy.yml'):
            self.bundle(play)
            with self.subTest(play=play),self.assertRaisesRegex(ValueError,'legacy or foreign'):
                guard.permit('erpc-r-delayed.service',self.command)
        self.assertFalse(any('kill' in arg or arg=='stop' for command in self.commands for arg in command))
    def test_same_native_play_foreign_contract_or_login_refuses(self):
        INSTALL(self.operation);inventory=self.bundle()
        host=next(iter(inventory['all']['hosts'].values()));host['solana_native_request']['contract']['inventory_id']='foreign'
        files.atomic(self.late/'bundle/inventory.yml',files.encoded(inventory))
        with self.assertRaises(ValueError):guard.permit('erpc-r-delayed.service',self.command)
        self.bundle();files.atomic(self.late/'sealed.json',files.encoded({'bundle':'a'*64,'login':1001,'group':1101}))
        with self.assertRaises(ValueError):guard.permit('erpc-r-delayed.service',self.command)
    def test_other_queued_active_or_restarting_run_blocks_without_signals(self):
        self.jobs='123 erpc-r-other.service start waiting\n'
        with self.assertRaises(ValueError):INSTALL(self.operation)
        self.assertFalse(self.dropin.exists())
        self.jobs='';self.units='erpc-r-other.service loaded inactive dead original\n'
        clean={'LoadState':'loaded','ActiveState':'inactive','SubState':'dead','MainPID':'0','ControlPID':'0','Restart':'no'}
        for field,value in [('ActiveState','activating'),('MainPID','100'),('ControlPID','101'),('Restart','always'),('LoadState','error')]:
            self.observed=dict(clean,**{field:value})
            with self.subTest(field=field),self.assertRaises(ValueError):INSTALL(self.operation)
        self.observed=clean;INSTALL(self.operation);guard.verify(self.operation)
        # Completed failed runs do not strand recovery, nor does the authenticated
        # current operation mistake itself for an unrelated queued run.
        self.observed=dict(clean,ActiveState='failed',SubState='failed')
        self.jobs='124 erpc-r-current.service start running\n';INSTALL(self.operation)
    def test_persistent_guard_receipt_failure_attempts_original_shutdown_without_publishing_condition(self):
        original=self.operation.run
        def command(args):
            if args[:2] in (['/usr/bin/systemctl','list-jobs'],['/usr/bin/systemctl','list-units']):return original(args)
            return self.fixture.service(args)
        self.operation.run=command
        with patch.object(guard,'install',INSTALL),patch.object(os,'fsync',side_effect=OSError('inert persistent guard sync failure')):
            with self.assertRaises(OSError):self.operation.retire()
        self.assertFalse(self.fixture.running);self.assertFalse(self.dropin.exists())
        self.assertEqual(self.fixture.unit.read_bytes(),self.fixture.unit_raw)

    def test_directory_or_condition_substitution_refuses_without_repair(self):
        INSTALL(self.operation);self.dropin.write_bytes(b'foreign override')
        with self.assertRaises(ValueError):INSTALL(self.operation)
        self.assertEqual(self.dropin.read_bytes(),b'foreign override')


if __name__=='__main__':
    result=unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(Guard))
    raise SystemExit(not result.wasSuccessful())

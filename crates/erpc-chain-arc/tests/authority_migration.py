#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Explicit legacy migration using actual capture/publication and simulated NSS/native effects."""
import hashlib
import os
import pathlib
import shutil
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import authority_lifecycle as lifecycle
import arc_files as files
import arc_migration as migration
import arc_process as process
import arc_release as release
import arc_storage as storage


class Migration(lifecycle.Lifecycle):
    def setUp(self):
        super().setUp()
        self.original = self.c.state(self.contract)
        uid,gid = self.original['service_uid'],self.original['service_gid']
        shutil.rmtree(self.c.ROOT)
        shutil.rmtree(self.c.path('/usr/local/lib/erpc/arc'))
        root = self.c.path('/var/lib/arc')
        root.chmod(0o750)
        record=self.real_stat(root);self.owners[(record.st_dev,record.st_ino)]=(uid,gid)
        for name,relative in [('execution','db/mdbx.dat'),('consensus','store.db')]:
            folder=root/name;folder.mkdir(mode=0o750)
            path=folder/relative;path.parent.mkdir(exist_ok=True)
            path.write_bytes(b'original legacy block history')
            for item in [folder,*folder.rglob('*')]:
                info=self.real_stat(item);self.owners[(info.st_dev,info.st_ino)]=(uid,gid)
        native=self.c.mkdir('/opt/arc/v0.8.1',mode=0o755)
        for component,name in process.BINARIES.items():
            self.c.write_bytes('/opt/arc/v0.8.1/'+name,b'inert native '+name.encode(),0o755)
        self.c.path('/opt/arc/current').symlink_to('/opt/arc/v0.8.1')
        self.c.mkdir('/opt/erpc/runs/inert/legacy-rendered')
        for component,name in process.UNITS.items():
            text='[Unit]\nDescription=public inert legacy '+component+'\n[Service]\nExecStart=/opt/arc/current/'+process.BINARIES[component]+' start\n'
            self.c.write_bytes('/etc/systemd/system/'+name,text.encode(),0o644)
            self.c.write_bytes('/opt/erpc/runs/inert/legacy-rendered/'+name,text.encode())
        self.evidence={'uid':uid,'gid':gid,'machine':self.c.machine(),
                       'highest':{'version':self.target['version'],'commit':self.target['commit']},
                       'proofs':{name:'a'*64 for name in ('passwd','group','machine','source')}}
        self.migration_request={'schema':'erpc-arc-original-authority-v1','action':'migration-check',
                                'contract':self.contract,'target':self.target,'policy':self.policy,
                                'evidence':self.evidence,'helpers':self.helper}
        self.c.calls.clear()

    # Do not run the inherited fresh lifecycle cases against this legacy fixture.
    test_prepare_install_bootstrap_promote_preserves_one_original_identity=None
    test_stop_during_initial_bootstrap_revokes_stale_completion_and_activation=None
    test_owned_bootstrap_quarantine_is_explicit_and_never_resets_active_history=None
    test_first_condition_refuses_changed_original_account_before_any_model_grant=None
    test_long_run_cannot_use_another_confirmed_preparation=None
    test_lost_reset_acknowledgement_repeats_the_same_quarantine_without_losing_bytes=None

    def migrate(self):
        result=self.c.dispatch(self.migration_request)
        self.c.write_bytes(result['archive'],self.archive)
        return self.c.dispatch(dict(self.migration_request,action='migrate'))

    def test_actual_migration_preserves_inode_bytes_key_and_original_numeric_identity(self):
        root=self.c.path('/var/lib/arc')
        old=root.stat().st_ino
        old_key=self.c.read('/etc/credstore.encrypted/arc-consensus-key')
        self.assertTrue(self.migrate()['stopped'])
        state=self.c.state(self.contract)
        self.assertEqual((state['service_uid'],state['service_gid']),(self.evidence['uid'],self.evidence['gid']))
        self.assertTrue(state['migrated'] and state['retired'])
        self.assertEqual(root.stat().st_ino,old)
        self.assertEqual(root.stat().st_uid,self.c.owner)
        self.assertEqual((root/'execution/db/mdbx.dat').read_bytes(),b'original legacy block history')
        self.assertEqual(self.c.read('/etc/credstore.encrypted/arc-consensus-key'),old_key)
        self.assertEqual(len([call for call in self.c.calls if call[1]=='stop']),3)
        repeat=self.migrate()
        self.assertTrue(repeat['runtime_unchanged'])
        self.assertIsNone(state['source_floor']['archive_sha256'])
        release.floor(self.c,state,self.target,opening=True)
        self.assertEqual(self.c.state(self.contract)['source_floor'],self.target)

    def test_wrong_history_or_unknown_unit_refuses_without_shutdown_or_ownership_changes(self):
        home=self.c.path('/var/lib/arc')
        self.evidence['machine']='b'*64
        with self.assertRaises(files.Refused):self.c.dispatch(self.migration_request)
        self.assertEqual(self.c.calls,[])
        self.evidence['machine']=self.c.machine()
        path=self.c.path('/etc/systemd/system/arc-consensus.service')
        path.write_text(path.read_text()+'ExecStop=/unrecognized\n')
        with self.assertRaises(files.Refused):self.c.dispatch(self.migration_request)
        self.assertEqual(self.c.calls,[])
        self.assertEqual(home.stat().st_uid,self.evidence['uid'])
        self.assertFalse(self.c.path('/etc/erpc/arc/authority/owner.json').exists())

    def test_legacy_symlink_database_parent_is_not_adopted_or_stopped(self):
        root=self.c.path('/var/lib/arc/execution')
        original=root/'db';retained=root/'retained';original.rename(retained)
        original.symlink_to(retained)
        with self.assertRaises(files.Refused):self.c.dispatch(self.migration_request)
        self.assertEqual(self.c.calls,[])
        self.assertTrue((retained/'mdbx.dat').exists())
        self.assertFalse(self.c.path('/etc/erpc/arc/authority/owner.json').exists())

    def test_interrupted_owner_publication_reuses_original_record_and_attempts_shutdown(self):
        result=self.c.dispatch(self.migration_request);self.c.write_bytes(result['archive'],self.archive)
        write=self.c.write
        fired=[]
        def interrupted(name,value,*args,**kwargs):
            write(name,value,*args,**kwargs)
            if name.endswith('/owner.json') and not fired:
                fired.append(True);raise OSError('inert post-owner publication interruption')
        with patch.object(self.c,'write',interrupted),self.assertRaises(OSError):
            self.c.dispatch(dict(self.migration_request,action='migrate'))
        self.assertTrue(any(call[1]=='stop' for call in self.c.calls))
        uid=self.c.json('/etc/erpc/arc/authority/owner.json')['service_uid']
        self.assertTrue(self.migrate()['stopped'])
        self.assertEqual(self.c.state(self.contract)['service_uid'],uid)
        self.assertEqual((self.c.path('/var/lib/arc/consensus/store.db')).read_bytes(),b'original legacy block history')


if __name__=='__main__':unittest.main()

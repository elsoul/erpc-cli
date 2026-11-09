# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Host source floors through production controller paths, with inert native clients."""
import copy
import os
from pathlib import Path
import shutil
import stat
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import authority_runtime as fixtures
import control
import eth_source_floor as floor


class SourceFloor(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.Runtime();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.state=self.f.state;self.expected=self.f.c

    def finish(self):
        self.f.install_target();self.state.put('snapshot.json',{'contract':self.expected})
        self.f.request('activate',intent=self.f.intent);self.f.calls.clear()

    def select(self,pair,operation='b'*32):
        original=self.f.root/'opt'/self.f.target['pair'];destination=self.f.root/'opt'/pair
        if not destination.exists():
            destination.mkdir()
            for client in floor.CLIENTS:
                shutil.copyfile(original/client,destination/client);(destination/client).chmod(0o555)
        self.f.target=dict(self.f.target,pair=pair);self.f.intent=operation

    def test_stale_inventory_and_single_client_downgrades_fail_before_shutdown_or_unit_publication(self):
        self.finish()
        for pair in ('reth-v2.8.0--lighthouse-v8.3.0','reth-v2.8.0--lighthouse-v8.4.0','reth-v2.9.0--lighthouse-v8.3.1'):
            self.select(pair)
            with self.assertRaisesRegex(ValueError,'below.*highest'):self.f.reserve_target()
            self.assertEqual(self.f.calls,[]);self.assertTrue(self.f.active)

    def test_same_opened_version_source_change_is_refused_even_when_other_client_advances(self):
        self.finish();self.select('reth-v2.8.1--lighthouse-v8.4.0')
        source={key:self.f.target[key] for key in ('pair','rpc_bind','metrics_bind','checkpoint')}
        source.update(reth_commit='9'*40,lighthouse_commit='2'*40,reth_archive='3'*64,lighthouse_archive='4'*64)
        with self.assertRaisesRegex(ValueError,'substitute'):
            self.f.request('reserve-deploy',intent=self.f.intent,target=source,operation='deploy')
        self.assertEqual(self.f.calls,[])

    def test_signed_acquisition_and_unit_install_do_not_raise_data_opening_floor(self):
        self.finish();before={c:self.state.get('source-'+c+'.json') for c in floor.CLIENTS}
        self.select('reth-v2.9.0--lighthouse-v8.4.0');self.f.install_target()
        self.assertEqual(before,{c:self.state.get('source-'+c+'.json') for c in floor.CLIENTS})
        self.assertFalse(any('start' in call or '--now' in call for call in self.f.calls))

    def test_snapshot_authorization_survives_recovery_and_prevents_old_manual_or_boot_source(self):
        self.finish();old=self.state.get('active.json');self.select('reth-v2.9.0--lighthouse-v8.4.0');self.f.install_target()
        self.state.remove('snapshot.json');self.f.request('bootstrap',intent=self.f.intent)
        self.assertEqual(self.state.get('source-reth.json')['pin']['version'],'v2.9.0')
        self.assertEqual(self.state.get('source-lighthouse.json')['pin']['version'],'v8.3.2')
        self.f.request('recover',intent=self.f.intent);self.f.calls.clear()
        # Low-level retained active receipt cannot bypass a source floor after
        # explicit recovery; the public start path remains fenced as well.
        with self.assertRaises(ValueError):control.ready(self.state,self.expected,old)
        with self.assertRaises(ValueError):self.f.request('start')
        with patch.object(control,'State',return_value=self.state):
            with self.assertRaises(ValueError):control.boot('guard','reth.service')
        self.assertFalse(any('start' in call or '--now' in call for call in self.f.calls))

    def test_visible_pending_floor_with_failed_durability_cannot_authorize_old_boot_or_start(self):
        self.finish();old=self.state.get('active.json');self.select('reth-v2.9.0--lighthouse-v8.4.0');self.f.install_target()
        self.state.remove('snapshot.json');self.f.calls.clear();original=self.state.put
        def fail(name,value):
            original(name,value)
            if name=='source-reth-pending.json':raise OSError('inert post-rename persistence failure')
        with patch.object(self.state,'put',side_effect=fail):
            with self.assertRaises(OSError):self.f.request('bootstrap',intent=self.f.intent)
        self.assertFalse(any('start' in call for call in self.f.calls))
        with self.assertRaisesRegex(ValueError,'below.*highest'):control.ready(self.state,self.expected,old)
        self.assertEqual(self.f.request('bootstrap',intent=self.f.intent)['snapshot'],'submitted')
        self.assertEqual(self.state.get('source-reth.json')['pin']['version'],'v2.9.0')

    def test_persistent_source_sync_failure_never_starts_but_emergency_stop_still_attempts_shutdown(self):
        self.f.install_target();self.f.calls.clear();actual=os.fsync
        def fail(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('inert persistent directory failure')
            actual(fd)
        with patch.object(os,'fsync',side_effect=fail):
            for _ in range(2):
                with self.assertRaises(OSError):self.f.request('bootstrap',intent=self.f.intent)
            with self.assertRaises(ValueError):self.f.request('stop')
        self.assertTrue(any(call[1]=='stop' for call in self.f.calls))
        self.assertFalse(any('start' in call or '--now' in call for call in self.f.calls))

    def test_actual_post_rename_directory_fsync_failure_keeps_pending_floor_closed_on_retries(self):
        self.finish();old=self.state.get('active.json');self.select('reth-v2.9.0--lighthouse-v8.4.0');self.f.install_target()
        self.state.remove('snapshot.json');self.f.calls.clear();actual=os.fsync
        def fail(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                pending=self.state.path('source-reth-pending.json')
                if pending.exists() and b'v2.9.0' in pending.read_bytes():raise OSError('inert actual post-rename directory fsync failure')
            actual(fd)
        with patch.object(os,'fsync',side_effect=fail):
            for _ in range(2):
                with self.assertRaises(OSError):self.f.request('bootstrap',intent=self.f.intent)
                with self.assertRaises(OSError):control.ready(self.state,self.expected,old)
        self.assertFalse(any('start' in call or '--now' in call for call in self.f.calls))
        self.assertEqual(self.state.get('source-reth.json')['pin']['version'],'v2.8.1')
        self.assertEqual(self.state.get('source-reth-pending.json')['pin']['version'],'v2.9.0')
        self.assertEqual(self.f.request('bootstrap',intent=self.f.intent)['snapshot'],'submitted')

    def test_missing_original_floor_is_not_reconstructed_from_active_or_nonempty_data(self):
        self.finish()
        for name in ('source-reth.json','source-reth-pending.json'):self.state.remove(name)
        active=self.state.get('active.json')
        with self.assertRaisesRegex(ValueError,'receipts are missing'):control.authorize_opening(self.state,self.expected,active)
        self.state.remove('active.json')
        with patch.object(floor,'empty_data',return_value=False):
            with self.assertRaisesRegex(ValueError,'receipts are missing'):control.authorize_opening(self.state,self.expected,active)

    def test_changed_layout_and_same_version_image_substitution_refuse(self):
        self.finish();active=copy.deepcopy(self.state.get('active.json'))
        qualified=self.state.get('qualified-'+active['intent']+'.json')
        qualified['target']['artifacts']['reth']['sha256']='e'*64
        active['receipt']['units']['target']=qualified['target'];self.state.put('qualified-'+active['intent']+'.json',qualified)
        with self.assertRaisesRegex(ValueError,'substitute'):control.opening_source(self.state,self.expected,active)
        layout=self.state.get('layout.json');layout['binding']['inode']=99;self.state.put('layout.json',layout)
        with self.assertRaisesRegex(ValueError,'authority differs'):floor.records(self.state,self.expected,'reth')


if __name__=='__main__':unittest.main()

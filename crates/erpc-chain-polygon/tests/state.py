# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Executable host ownership, two-client ordering and failure fences."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))

@unittest.skipUnless(os.name=='posix','managed-host locks require POSIX')
class State(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('polygon_state_fixture',ROOT/'templates/scripts/state.py')
        self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        for directory in ('etc/polygon','opt/erpc','var/lib/polygon'):(self.root/directory).mkdir(parents=True)
        self.profile=json.loads((ROOT/'networks/amoy.json').read_text())
        self.expected=self.module.contract('amoy','i'*26,'x86_64',self.profile['bor_genesis_hash'],self.profile['heimdall_genesis']['sha256'])
        self.calls=[];self.active=True;self.capacity=(2_000_000_000_000,0)
        self.state=self.module.State(self.root,self.command,usage=lambda:self.capacity,owner=os.getuid(),proof=type('FixtureAuthority',(),{'initial':lambda self:None,'can_start':lambda self,*args:None,'unoccupied':lambda self:None,'quiescent':lambda self:None,'startable':lambda self,*args:None,'listener':lambda self,*args:('fixture',)})())
        self.state.ownership(self.expected,initial=True)
        import volume_fixture
        volume_fixture.attach(self,self.state)
        volume_fixture.bind(self.state,self.expected)
        self.intent='a'*32
    def command(self,args,**kwargs):
        self.calls.append(args)
        value=b''
        if args[:2]==['systemctl','show']:
            value=(b'123' if self.active else b'0') if '--property=MainPID' in args else b'loaded'
        if args[:2]==['systemctl','is-active']:value=b'active' if self.active else b'inactive'
        if args[:2]==['systemctl','stop'] or args[:3]==['systemctl','disable','--now']:self.active=False
        return subprocess.CompletedProcess(args,0,value,b'')
    def prepare(self,profile=None):
        with self.state.locked():self.state.prepare(self.expected,self.intent,profile or self.profile,'b'*64)
    def test_validator_phase_and_original_signer_are_bound_to_the_exact_preparation(self):
        expected=self.module.contract('amoy','i'*26,'x86_64',self.profile['bor_genesis_hash'],
            self.profile['heimdall_genesis']['sha256'],'validator','0x'+'ab'*20,'0x'+'cd'*20)
        profile=copy.deepcopy(self.profile)
        profile['validator']={'phase':'observing','signer':expected['signer'],
            'sentries':[{'address':'192.0.2.2','bor_node_id':'ab'*64,'heimdall_node_id':'cd'*20}]}
        with self.assertRaises(ValueError):self.module.target(self.expected,profile)
        with self.assertRaises(ValueError):self.module.target(expected,self.profile)
        saved=self.state.read('/etc/polygon/storage.json');saved['contract']=expected
        self.state.write('/etc/polygon/storage.json',saved)
        self.state.write('/etc/polygon/contract.json',dict(expected,runtime_protocol=3))
        self.state.prepare(expected,self.intent,profile,'b'*64)
        active=copy.deepcopy(profile);active['validator']['phase']='active'
        with self.assertRaises(ValueError):self.state.phase(expected,self.intent,active,'b'*64)
        self.module.monotonic(expected,profile,active)
        with self.assertRaisesRegex(ValueError,'history'):self.module.monotonic(expected,active,profile)
        wrong=copy.deepcopy(profile);wrong['validator']['signer']=expected['stake_owner']
        count=len(self.calls)
        with self.assertRaises(ValueError):self.state.prepare(expected,'c'*32,wrong,'b'*64)
        self.assertEqual(len(self.calls),count)

    def test_foreign_inventory_and_retained_history_cannot_be_adopted(self):
        foreign=dict(self.expected,owner='j'*26)
        with self.assertRaises(ValueError):self.state.ownership(foreign,initial=True)
        with self.assertRaises(ValueError):self.state.prepare(foreign,self.intent,self.profile,'b'*64)
        self.assertFalse(self.calls)
        self.state.path('/etc/polygon/contract.json').unlink()
        (self.root/'var/lib/polygon/history').write_text('retained native history fixture')
        with self.assertRaises(ValueError):self.state.ownership(self.expected,initial=True)
        self.assertFalse(self.calls)
    def test_missing_contract_refuses_retained_credential_or_helper_pointer(self):
        self.state.path('/etc/polygon/contract.json').unlink()
        for name in ('/etc/credstore.encrypted/polygon','/usr/local/lib/erpc/polygon/current'):
            path=self.state.path(name);path.parent.mkdir(parents=True,exist_ok=True)
            path.symlink_to('/unavailable-original-fixture')
            with self.assertRaises(ValueError):self.state.ownership(self.expected,initial=True)
            path.unlink()
        self.assertFalse(self.calls)

    def test_each_layer_has_an_independent_monotonic_release_floor(self):
        for layer in ('bor','heimdall'):
            future=copy.deepcopy(self.profile)
            old=future['releases'][layer]['tag'];new='v99.0.0'
            future['releases'][layer]=json.loads(json.dumps(future['releases'][layer]).replace(old,new))
            self.state.write('/etc/polygon/installed.json',{'profile':future})
            with self.assertRaises(ValueError):self.prepare()
            self.assertTrue(self.active);self.assertFalse(self.calls)
        self.state.path('/etc/polygon/installed.json').unlink()
        # A higher historical source can be retained even when this CLI cannot
        # execute it. Never stage an unqualified future pair just to create a floor.
        with self.assertRaises(ValueError):self.prepare(future)
        self.state.write('/etc/polygon/intent.json',{'intent':self.intent,'profile':future,'helpers':'b'*64})
        self.state.invalidate('stopped')
        with self.assertRaises(ValueError):self.prepare()
    def test_profile_mismatch_or_failed_drain_leaves_startup_fenced(self):
        original=self.state.run
        def failed(args,**kwargs):
            if args[:2]==['systemctl','stop'] or args[:3]==['systemctl','disable','--now']:return subprocess.CompletedProcess(args,0,b'',b'')
            return original(args,**kwargs)
        self.state.run=failed
        with self.assertRaises(ValueError):self.prepare()
        self.assertTrue(self.state.path('/etc/polygon/preparing').exists())
        altered=copy.deepcopy(self.profile);altered['configs']['bor']['sha256']='0'*64
        with self.assertRaises(ValueError):self.state.phase(self.expected,self.intent,altered)
        self.state.invalidate('stop')
        with self.assertRaises(ValueError):self.state.phase(self.expected,self.intent,self.profile)
    def test_capacity_counts_allocated_data_and_never_prevents_a_stop(self):
        self.capacity=(100_000_000_000,0)
        with self.assertRaises(ValueError):self.prepare()
        self.assertTrue(self.active);self.assertFalse(self.calls)
        self.capacity=(100_000_000_000,1_500_000_000_000)
        self.prepare();self.assertFalse(self.active)
        self.capacity=(0,1_600_000_000_000);self.active=True
        with self.assertRaises(ValueError):self.state.capacity(self.expected)
        self.state.stop(disable=True);self.assertFalse(self.active)
    def test_os_reserve_is_checked_and_only_database_usage_counts_toward_capacity(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        self.state.usage=None
        root_free=1024**3
        def stat(path):
            return SimpleNamespace(f_bavail=root_free if str(path).endswith('/opt/polygon') else 2_000_000_000_000,f_frsize=1)
        with patch.object(self.module.os,'statvfs',side_effect=stat):
            with self.assertRaises(ValueError):self.state.capacity(self.expected)
            root_free=3*1024**3
            result=self.state.capacity(self.expected)
            self.assertEqual(result['allocated_bytes'],0)
            self.assertEqual(result['root_available_bytes'],root_free)
        self.assertFalse(self.calls)

    def test_a_removed_service_definition_does_not_hide_a_still_running_process(self):
        original=self.state.run
        def missing(args,**kwargs):
            if args[:2]==['systemctl','show'] and '--property=LoadState' in args:
                return subprocess.CompletedProcess(args,0,b'not-found',b'')
            return original(args,**kwargs)
        self.state.run=missing
        self.state.stop()
        self.assertFalse(self.active)
        self.assertTrue(any(args[:2]==['systemctl','stop'] for args in self.calls))

    def test_genesis_and_workflow_sources_are_not_runtime_redirectable(self):
        for field in ('genesis','certificate','package'):
            bad=copy.deepcopy(self.profile)
            if field=='genesis':bad['heimdall_genesis']['url']='https://github.com/unrelated'
            elif field=='certificate':bad['releases']['bor']['certificate_identity']='https://github.com/unrelated'
            else:bad['releases']['bor']['assets']['x86_64']['package']['url']='https://github.com/unrelated'
            with self.assertRaises(ValueError):self.prepare(bad)
        self.assertFalse(self.calls)

if __name__=='__main__':unittest.main()

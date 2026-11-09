# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual controller/state orchestration with inert process, account and network edges."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
SOURCE=Path(__file__).parents[1]/'templates/aqa';sys.path.insert(0,str(SOURCE))
import erpc_aqa_common as common
import erpc_aqa_state as states
import erpc_aqa_host as host
import erpc_aqa_public as public
spec=importlib.util.spec_from_file_location('aqa_controller_fixture',SOURCE/'control.py')
control=importlib.util.module_from_spec(spec);spec.loader.exec_module(control)


class Runtime(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.state=states.State(self.root)
        self.c={'schema':1,'profile':'hyperliquid-aqa','owner':'a'*32,'network':'testnet','host_binding':'b'*64,
                'identity':{'validator':'0x'+'a'*40,'consensus_signer':'0x'+'b'*40,'agent_master':'0x'+'c'*40,
                            'agent':'0x'+'d'*40,'agent_public_key':'04'+'11'*64,'agent_name':'erpc-aqa'}}
        self.state.put('owner.json',{'contract':self.c,'machine':'inert machine binding'})
        self.account={'uid':995,'gid':995};self.identities={host.accounts.NATIVE:self.account}
        for name in ('accounts.json','account-reservation.json'):self.state.put(name,self.identities)
        self.catalog=json.loads((SOURCE/'catalog.json').read_bytes())
        self.target={'id':'aqa-'+self.catalog['version'],'sha256':self.catalog['artifact']['sha256'],
                     'signed_at':self.catalog['artifact']['signed_at'],'helper_sha':'e'*64,'config_id':'f'*64}
        self.intent='b'*32
        reader=patch.object(states,'read',lambda path:common.read(path,owner=os.getuid()))
        reader.start();self.addCleanup(reader.stop)
        self.state.authorize(self.c,self.intent,self.target)
        self.state.begin(self.c,self.intent,self.target,lambda:None)
        self.binary=self.root/'publish_daemon'
        self.receipt={'units':{},'processes':{str(self.binary):{'argv':[str(self.binary)],'sha256':'f'*64}},
                      'runtime_sha256':'0'*64,'firewall':{'run':'c'*32,'bundle':'d'*64}}
        self.state.finish(self.c,self.intent,self.receipt)
        self.patches=[]
        def install(obj,name,value):
            p=patch.object(obj,name,value);p.start();self.patches.append(p)
        self.addCleanup(lambda:[p.stop() for p in reversed(self.patches)])
        install(host,'ROOT',self.root);install(control,'ROOT',self.root)
        install(states,'read',lambda path:common.read(path,owner=os.getuid()))
        install(host,'read',lambda path,limit=1048576:common.read(path,limit,owner=os.getuid()))
        install(host,'owned',lambda c:self.owned(c));install(host,'protected_paths',lambda **_:None)
        install(host,'catalog',lambda:self.catalog)
        install(host.accounts,'accounts',lambda value:value)
        install(host,'qualified',lambda request,exact=True:(host.contract(request['contract']),request['target'],request['policy'],self.catalog))
        self.stops=[];install(host,'stop_owned',lambda c:self.stops.append(c['owner']))
        self.calls=[];install(host,'execute',lambda argv,**_:self.calls.append(argv) or types.SimpleNamespace(stdout=b''))
        install(host.artifact,'check',lambda _:self.binary)
        install(host.process,'quiescent',lambda *args:None)
        install(host.process,'prove',lambda *args:'99')
        install(host.process,'scan',lambda *args:({123:'99'},False))
        install(host,'qualify',lambda c,intent=None,manual=False:self.qualify(c,intent,manual))
        self.service={'ActiveState':'active','SubState':'running','MainPID':123}
        install(host,'service',lambda _:self.service)

    def owned(self,c):self.state.check(c);return self.state
    def qualify(self,c,intent=None,manual=False):
        value=self.state.guard(c,intent,manual)
        return self.state,self.account,value,{'approval':{},'validator_active':True,'observed_core_time':1}
    def dispatch(self,action,**extra):return control.dispatch({'action':action,'contract':self.c,**extra})

    def test_already_running_original_process_is_idempotent_and_activation_is_consumed(self):
        result=self.dispatch('activate',intent=self.intent)
        self.assertTrue(result['already_running']);self.assertEqual(self.state.get('operation.json')['intent'],None)
        self.assertEqual(self.stops,[]);self.assertEqual(self.calls,[])
        self.assertTrue(self.dispatch('start')['already_running'])

    def test_skipped_condition_cannot_consume_intent_or_claim_started(self):
        self.service={'ActiveState':'inactive','SubState':'dead','MainPID':0}
        with self.assertRaises(ValueError):self.dispatch('activate',intent=self.intent)
        self.assertEqual(self.stops,[self.c['owner']])
        self.assertTrue((self.root/'stopped').exists());self.assertTrue((self.root/'activation-revoked').exists())
        self.assertTrue(any('start' in command for command in self.calls))
        self.assertEqual(self.state.get('installed.json')['operation']['intent'],self.intent)

    def test_stale_preparation_and_activation_never_cancel_the_current_owner_operation(self):
        self.state.authorize(self.c,'c'*32,self.target)
        before={path.name:path.read_bytes() for path in self.root.iterdir()}
        with self.assertRaises(ValueError):self.dispatch('prepare',intent=self.intent,target=self.target,policy={'management_allow':[]})
        with self.assertRaises(ValueError):self.dispatch('activate',intent=self.intent)
        self.assertEqual(self.stops,[])
        self.assertEqual({path.name:path.read_bytes() for path in self.root.iterdir()},before)

    def test_failed_stop_storage_attempts_owned_shutdown_and_never_stops_foreign_scope(self):
        with patch.object(states.State,'put',side_effect=OSError('inert full disk')),\
             patch.object(states.State,'marker',side_effect=OSError('inert full disk')):
            for action in ('stop','destroy'):
                with self.assertRaises(ValueError):self.dispatch(action)
        self.assertEqual(self.stops,[self.c['owner']]*2)
        wrong=dict(self.c,owner='f'*32)
        with self.assertRaises(ValueError):control.dispatch({'action':'stop','contract':wrong})
        self.assertEqual(len(self.stops),2)

    def test_observer_after_interrupted_consume_still_stops_revoked_agent(self):
        self.assertIsNotNone(self.state.get('operation.json')['intent'])
        with patch.object(host,'qualify',side_effect=public.Revoked('inert observed removed approval')):
            with self.assertRaises(ValueError):host.observe(self.c)
        self.assertEqual(self.stops,[self.c['owner']]);self.assertTrue((self.root/'agent-revoked').exists())

    def test_idle_pending_activation_is_not_cancelled_by_an_old_observer(self):
        self.service={'ActiveState':'inactive','SubState':'dead','MainPID':0}
        before=copy.deepcopy(self.state.get('operation.json'))
        self.assertIn('awaits',host.observe(self.c)['observer'])
        self.assertEqual(self.state.get('operation.json'),before);self.assertEqual(self.stops,[])

    def test_revocation_marker_failure_still_attempts_original_shutdown(self):
        actual=self.state.marker
        def fail(name):
            if name=='agent-revoked':raise OSError('inert first revocation save failure')
            actual(name)
        with patch.object(self.state,'marker',fail),self.assertRaisesRegex(ValueError,'not persisted'):
            host.reject_runtime(self.c,public.Revoked('inert replaced approval'))
        self.assertEqual(self.stops,[self.c['owner']]);self.assertTrue((self.root/'stopped').exists())

    def test_candidate_configuration_and_retirement_survive_failed_startup(self):
        self.state.cancel(self.c,True,lambda:None)
        before={path.name:path.read_bytes() for path in self.root.iterdir()}
        for action in ('start','restart'):
            with self.assertRaises(ValueError):self.dispatch(action)
        self.assertEqual(self.stops,[]);self.assertEqual({path.name:path.read_bytes() for path in self.root.iterdir()},before)


if __name__=='__main__':unittest.main()

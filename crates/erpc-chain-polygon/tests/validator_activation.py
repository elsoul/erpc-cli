# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original admission transition/retry fixtures; no network, key or transaction."""
import copy
import base64
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock,patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))


def module(name):
    spec=importlib.util.spec_from_file_location('polygon_activation_fixture_'+name,ROOT/'tests'/(name+'.py'))
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result


@unittest.skipUnless(os.name=='posix','transition uses real POSIX ownership/history receipts')
class Transition(unittest.TestCase):
    def setUp(self):
        import validator_activation as activation
        import identity
        self.module=activation
        self.fixture=module('validator_runtime').Finalization();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        fixture=self.fixture;fixture.finalize()
        self.state,self.controller,self.expected=fixture.state,fixture.control,fixture.expected
        self.target=copy.deepcopy(fixture.profile);self.target['validator']['phase']='active'
        self.request=dict(fixture.request,action='authorize-active',profile=self.target,intent='c'*32,
            credential={'execution':{'url':'https://github.com'}})
        original=identity.receipt(self.state,self.expected)
        self.observation={'network':self.expected['network'],'signer':self.expected['signer'],
            'registered':True,'parent_active':True,'parent_validator':{'owner':self.expected['stake_owner'],'id':'7'},
            'active_member':{'public_key':original['validator']['public_key'],'id':7},'active_on_both_observations':True}
        # Old installed revision qualification is independently exercised by
        # real installer/seal tests. Here no unit/native transport is executed.
        self.installed=dict(fixture.installed)
        self.install=patch.object(activation.install,'installed',return_value=self.installed);self.install.start();self.addCleanup(self.install.stop)
        self.owned_function=activation.owned_observer;self.snapshot_function=activation.admission.snapshot
        self.observer=patch.object(activation,'owned_observer',return_value=self.observation).start();self.addCleanup(patch.stopall)
        self.parent=patch.object(activation,'parent_query',return_value=Mock()).start()
        self.snapshot=patch.object(activation.admission,'snapshot',return_value=self.observation).start()
    def authorize(self):return self.controller.dispatch(self.request)
    def test_actual_observer_pipeline_requires_progress_exact_key_and_stable_owned_listeners(self):
        import identity
        observer=module('observe').Observer();observer.setUp();observer.profile=self.installed['profile']
        chain=module('admission').Admission();chain.setUp();chain.signer=self.expected['signer']
        chain.validator['signer']=chain.signer
        chain.validator['pub_key']=base64.b64encode(bytes.fromhex(self.observation['active_member']['public_key'][2:])).decode()
        contracts=chain.module.CONTRACTS[self.expected['network']]
        def query(port,path='/',payload=None):
            if port==1317 and path=='/stake/validators-set':return chain.result
            if port==9545 and payload['method']=='eth_call':
                result=chain.query(port,path,payload)
                if payload['params'][0]['data'].startswith(chain.module.SELECTORS['owner']):
                    result['result']='0x'+chain.module.word(int(self.expected['stake_owner'],16))
                return result
            if port==9545 and payload['method']=='eth_getBlockByNumber' and payload['params'][0] in ('finalized','0x64'):
                return chain.query(port,path,payload)
            result=observer.query(port,path,payload)
            if port==1317:
                result['params']['chain_params'].update(staking_manager_address=contracts['stake'],root_chain_address=contracts['root'])
            return result
        self.state.path('/etc/polygon/preparing').unlink()
        self.controller.sleep=lambda _:setattr(observer,'height',observer.height+3)
        manager=self.fixture.manager
        manager.health=Mock(return_value={'ready':True});manager.record=Mock(return_value=self.state.read(self.fixture.broker_runtime.CONTAINER))
        manager.token=self.fixture.original_container_token
        original=identity.receipt(self.state,self.expected)
        snapshot=lambda profile,signer,query:self.snapshot_function(profile,signer,query,clock=lambda:1200)
        with patch.object(self.module.observe,'ValidatorQuery',return_value=query),patch.object(self.module.admission,'snapshot',side_effect=snapshot):
            result=self.owned_function(self.controller,self.expected,self.installed,original)
            self.assertTrue(result['active_on_both_observations']);manager.health.assert_called_once()
            observer.catching=True
            with self.assertRaises(ValueError):self.owned_function(self.controller,self.expected,self.installed,original)
            observer.catching=False;chain.calls=0
            with patch.object(self.state.proof,'listener',side_effect=[('original',)]*3+[('changed',)]):
                with self.assertRaises(ValueError):self.owned_function(self.controller,self.expected,self.installed,original)

    def test_authorize_is_durable_before_any_stop_and_retry_keeps_original_observer_evidence(self):
        before=self.state.path('/var/lib/polygon/heimdall/data/priv_validator_state.json').read_bytes()
        result=self.authorize();self.assertFalse(result['activated']);self.assertFalse(result['ready'])
        self.observer.assert_called_once();self.snapshot.assert_called_once()
        saved=self.state.read(self.module.PERMIT)
        self.assertEqual(saved['intent'],'c'*32);self.assertTrue(saved['observer_verified'])
        self.observer.reset_mock();self.request['intent']='d'*32
        self.state.path('/etc/polygon/stopped').touch()
        self.authorize();self.observer.assert_not_called()
        self.assertEqual(self.state.path('/var/lib/polygon/heimdall/data/priv_validator_state.json').read_bytes(),before)
        self.module.require_permit(self.state,self.expected,'d'*32,self.target,self.controller.helpers,before_prepare=True)
        self.assertNotIn('configuration_sha256',result)
    def test_failed_authorization_write_never_stops_the_healthy_observer(self):
        write=self.state.write
        def fail(name,value,*args,**kwargs):
            if name==self.module.PERMIT:raise OSError('inert durable admission failure')
            return write(name,value,*args,**kwargs)
        with patch.object(self.state,'write',side_effect=fail),patch.object(self.state,'prepare') as prepare:
            with self.assertRaises(OSError):self.authorize()
            prepare.assert_not_called()
        self.assertFalse(self.state.path(self.module.PERMIT).exists())
    def test_cancelled_authorization_or_another_provider_never_allows_preparation(self):
        self.authorize();self.state.path('/etc/polygon/stopped').touch()
        with self.assertRaises(ValueError):self.module.require_permit(self.state,self.expected,'c'*32,self.target,self.controller.helpers,before_prepare=True)
        self.request['intent']='d'*32;self.authorize()
        receipt=self.state.read('/etc/polygon/upstream.json');receipt['configuration_sha256']='f'*64
        self.state.write('/etc/polygon/upstream.json',receipt)
        with self.assertRaises(ValueError):self.module.require_permit(self.state,self.expected,'d'*32,self.target,self.controller.helpers,credential=True)
    def test_changed_parent_owner_membership_or_original_key_never_reuses_a_prior_authorization(self):
        self.authorize()
        for value in (dict(self.observation,parent_active=False),dict(self.observation,parent_validator={'owner':'0x'+'3'*40,'id':'7'})):
            self.snapshot.return_value=value
            with self.assertRaises(ValueError):self.authorize()
        self.snapshot.return_value=self.observation
        receipt=self.state.read('/etc/polygon/identity.json');receipt['validator']['public_key']='0x04'+'b'*128
        self.state.write('/etc/polygon/identity.json',receipt)
        with self.assertRaises(ValueError):self.authorize()
    def test_active_history_without_original_observer_proof_is_not_adopted(self):
        self.installed['profile']=self.target
        with self.assertRaises(ValueError):self.authorize()
        self.observer.assert_not_called();self.parent.assert_not_called()


if __name__=='__main__':unittest.main()

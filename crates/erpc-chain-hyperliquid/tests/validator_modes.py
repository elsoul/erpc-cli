# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual validator lifecycle routes with inert native/signing boundaries."""
import copy
import sys
from unittest.mock import patch
import unittest
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import phases_test as phases
import erpc_hl_units as units
import erpc_hl_validator as custody
import erpc_hl_validator_public as public
from validator_custody import PUBLIC


class ValidatorModes(unittest.TestCase):
    def setUp(self):
        self.f=phases.Phases();self.f.setUp();self.addCleanup(self.f.tearDown)
        self.f.contract.update(role='validator',validator={'validator':'0x'+'ab'*20,
            'signer':'0x7e5f4552091a69125d5dfcb7b8c2659029395bdf','signer_public_key':PUBLIC,'max_hot_usdc':'0.01'})
        self.f.state.put('owner.json',{'contract':self.f.contract})
        self.f.target['mode']='follower'
        self.membership={'registered':True,'jailed':True,'active':False}
        self.funding=patch.object(public,'funding',return_value={'signer_perps_usdc':'0.001'}).start()
        self.registered=patch.object(public,'registration',side_effect=lambda *_:dict(self.membership)).start()
        self.identity=patch.object(custody,'identity',return_value={'plaintext_sha256':'e'*64}).start()
        self.path=patch.object(custody,'native_path',return_value={}).start()
        self.observed=patch.object(phases.host,'owned_observation',return_value=({'ready':True},[])).start()
        self.addCleanup(patch.stopall)

    def active_target(self):
        self.f.intent='d'*32;self.f.target['mode']='validator'

    def test_initial_follower_requires_explicit_mode_and_public_registration_before_activation(self):
        self.f.install()
        self.identity.assert_not_called()
        self.active_target();self.f.authorize();self.membership['registered']=False
        with self.assertRaisesRegex(ValueError,'registration'):self.f.prepare()
        self.assertFalse((self.f.root/'validator-activation.json').exists())
        self.membership['registered']=True;self.membership['jailed']=False
        with self.assertRaisesRegex(ValueError,'jailed'):self.f.prepare()
        self.membership['jailed']=True;self.observed.return_value=({'ready':False},[])
        with self.assertRaisesRegex(ValueError,'synchronized'):self.f.prepare()
        self.assertFalse((self.f.root/'validator-activation.json').exists())

    def test_interrupted_first_activation_reuses_only_exact_durable_follower_proof(self):
        self.f.install();self.active_target();self.f.authorize()
        with patch.object(phases.host.artifact,'install',side_effect=OSError('inert acquisition failure')),self.assertRaises(OSError):self.f.prepare()
        self.assertTrue((self.f.root/'validator-activation.json').exists())
        self.assertTrue((self.f.root/'installing.json').exists())
        self.observed.side_effect=ValueError('follower is now stopped')
        self.funding.side_effect=ValueError('unsolicited later deposit does not revoke original retry')
        self.f.intent='e'*32;self.f.authorize();self.f.prepare()
        self.f.confirmed=self.f.receipt;self.f.calls.clear()
        self.assertTrue(self.f.activate()['started'])
        starts=[call for call in self.f.calls if isinstance(call,tuple) and 'start' in call]
        self.assertEqual(len(starts),1);self.assertNotIn('erpc-hyperliquid-rpc.service',starts[0])
        self.assertEqual(self.f.state.get('installed.json')['operation']['target']['mode'],'validator')
        self.assertEqual((self.f.root/'retained-native-data').read_bytes(),b'never delete')

    def test_failed_activation_proof_durability_or_changed_retry_target_never_stops_follower(self):
        self.f.install();self.active_target();self.f.authorize();self.f.calls.clear()
        original=phases.lifecycle.State.put
        def fail(state,name,value):
            if name=='validator-activation.json':raise OSError('inert disk fault')
            return original(state,name,value)
        with patch.object(phases.lifecycle.State,'put',fail),self.assertRaises(OSError):self.f.prepare()
        self.assertNotIn('owned-stop',self.f.calls)
        self.f.prepare();self.f.intent='e'*32
        self.f.policy['management_allow']=['192.0.2.2/32']
        self.f.target['config_id']=phases.common.digest(phases.common.json_bytes(self.f.policy))
        self.f.authorize();self.f.calls.clear()
        with self.assertRaisesRegex(ValueError,'retry differs'):self.f.prepare()
        self.assertNotIn('owned-stop',self.f.calls)

    def test_explicit_recovery_can_qualify_new_target_only_after_new_healthy_follower(self):
        self.f.install();self.active_target();self.f.authorize();self.f.prepare()
        self.f.invoke('recover-preparation')
        self.f.intent='e'*32;self.f.target['mode']='follower';self.f.install()
        self.f.intent='f'*32;self.f.target['mode']='validator'
        self.f.policy['management_allow']=['192.0.2.2/32']
        self.f.target['config_id']=phases.common.digest(phases.common.json_bytes(self.f.policy))
        self.f.authorize();self.observed.side_effect=ValueError('new follower is not healthy')
        with self.assertRaises(ValueError):self.f.prepare()
        self.observed.side_effect=None;self.observed.return_value=({'ready':True},[])
        self.f.prepare()
        self.assertEqual(self.f.state.get('validator-activation.json')['target'],self.f.target)

    def test_visible_activation_proof_is_resynced_before_resuming_owned_shutdown(self):
        self.f.install();self.active_target();self.f.authorize()
        original=phases.lifecycle.State.put
        def publish_then_fail(state,name,value):
            original(state,name,value)
            if name=='validator-activation.json':raise OSError('inert post-rename durability fault')
        self.f.calls.clear()
        with patch.object(phases.lifecycle.State,'put',publish_then_fail),self.assertRaises(OSError):self.f.prepare()
        self.assertTrue((self.f.root/'validator-activation.json').exists())
        self.assertNotIn('owned-stop',self.f.calls)
        with patch.object(phases.lifecycle.State,'put',publish_then_fail),self.assertRaises(OSError):self.f.prepare()
        self.assertNotIn('owned-stop',self.f.calls)
        self.f.prepare();self.assertIn('owned-stop',self.f.calls)

    def test_original_active_mode_cannot_downgrade_and_stop_does_not_depend_on_registration(self):
        self.f.install();self.active_target();self.f.install()
        self.membership['registered']=False
        self.f.invoke('stop');self.assertTrue((self.f.root/'stopped').exists())
        self.f.intent='e'*32;self.f.target['mode']='follower';self.f.authorize()
        with self.assertRaisesRegex(ValueError,'silently'):self.f.prepare()
        self.assertEqual((self.f.root/'retained-native-data').read_bytes(),b'never delete')

    def test_unknown_registration_never_turns_healthy_local_node_into_ready_validator(self):
        self.f.install();self.active_target();self.f.install()
        installed=self.f.state.get('installed.json');profile={'network':'inert'}
        self.registered.side_effect=ValueError('inert public outage')
        with patch.object(phases.host,'ready',return_value=(installed,self.f.identities,profile)):
            result=phases.host.observe(self.f.contract)
        self.assertFalse(result['ready']);self.assertEqual(result['validator']['state'],'unknown')
        self.assertIn('inspection_error',result)

    def test_native_units_bind_original_numeric_recipient_and_condition_before_credential_load(self):
        for network in ('mainnet','testnet'):
            contract=dict(self.f.contract,network=network)
            follower=units.render(contract,{'id':'visor-'+'b'*16},self.f.identities,'follower')['erpc-hyperliquid-node.service']
            active=units.render(contract,{'id':'visor-'+'b'*16},self.f.identities,'validator')['erpc-hyperliquid-node.service']
            self.assertNotIn('LoadCredentialEncrypted=',follower);self.assertNotIn('node_config.json',follower)
            self.assertIn('User=995\nGroup=995\n',active)
            self.assertEqual(active.count('ExecCondition='),1)
            self.assertIn(' condition '+contract['owner'],active)
            self.assertIn(' guard-validator '+contract['owner'],active)
            self.assertIn('BindReadOnlyPaths=%d/'+custody.NAME+':',active)
            self.assertIn('LimitCORE=0',active);self.assertIn('run-validator',active)
            self.assertNotIn(self.f.contract['validator']['signer_public_key'],active)
        bad=copy.deepcopy(self.f.identities);bad[phases.host.setup.NATIVE]['uid']=False
        with self.assertRaises(ValueError):units.render(self.f.contract,{'id':'visor-'+'b'*16},bad,'validator')

    def test_condition_checks_original_accounts_without_reading_runtime_credential(self):
        self.f.install();self.active_target();self.f.install()
        with patch.object(phases.sys,'argv',['control.py','condition',self.f.contract['owner']]), \
             patch.object(phases.host,'recorded_accounts',side_effect=ValueError('inert original NSS drift')), \
             patch.object(custody,'verify_runtime') as decrypted,self.assertRaisesRegex(ValueError,'NSS'):
            phases.control.main()
        decrypted.assert_not_called()


if __name__=='__main__':unittest.main()

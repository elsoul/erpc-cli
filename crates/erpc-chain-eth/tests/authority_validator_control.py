# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual dispatch and original state cancellation with inert native effects."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import authority_validator_keys as fixtures
import eth_validator_control as control
import eth_validator_keys as keys


class Controller(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.Keys();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.s=self.f.state;self.c=self.f.c;self.plan=self.f.plan;self.intent='d'*32
        self.source={'pair':'reth-v2.8.1--lighthouse-v8.3.2','reth_commit':'a'*40,'lighthouse_commit':'b'*40,
                     'reth_archive':'c'*64,'lighthouse_archive':'d'*64,'fee_recipient':'0x'+'1'*40,'renew_transport':False}
        artifacts={'reth':{'sha256':'e'*64},'lighthouse':{'sha256':'f'*64}}
        self.target={'pair':self.source['pair'],'fee_recipient':self.source['fee_recipient'],'artifacts':artifacts}
        self.s.authorize(self.c,self.intent,self.source,'deploy')
        control.floor.authorize(self.s,self.c,self.plan,self.source,artifacts)
        self.s.begin(self.c,self.intent,lambda:None)
        self.s.put('qualified-'+self.intent+'.json',{'source':self.source,'target':self.target})
        self.s.publish(self.c,self.intent,{'units':{'target':self.target,'processes':{}}});self.s.consume(self.c,self.intent)
        self.f.imported();self.stops=[]
        self.f.base.install(control,'shutdown',lambda *_args,**_kwargs:self.stops.append(True))

    def request(self,action,**fields):
        return control.dispatch(self.s,self.c,dict(owner=self.c['owner'],action=action,**fields))

    def test_foreign_scope_refuses_before_shutdown_or_private_backup(self):
        original=self.s.get('owner.json')
        with self.assertRaises(ValueError):control.dispatch(self.s,self.c,{'owner':'foreign','action':'stop'})
        wrong=dict(self.c,network='mainnet')
        with self.assertRaises(ValueError):control.dispatch(self.s,wrong,{'owner':wrong['owner'],'action':'custody-backup'})
        self.assertEqual(self.stops,[]);self.assertEqual(self.s.get('owner.json'),original)

    def test_failed_permission_and_generation_persistence_still_attempts_owned_shutdown(self):
        for failing in ('signer-permission.json','halt.json','operation.json'):
            with self.subTest(failing=failing):
                real=self.s.put;self.stops.clear()
                def fail(name,value):
                    if name==failing:raise OSError('inert original persistence fault')
                    return real(name,value)
                with patch.object(self.s,'put',side_effect=fail),self.assertRaises(ValueError):self.request('stop')
                self.assertEqual(self.stops,[True])
                self.assertTrue(self.s.exists('signer-history.json'));self.assertTrue(self.s.exists('signer-original.cred'))

    def test_stopped_old_deploy_never_reaches_supporting_service_start(self):
        intent='e'*32;self.s.authorize(self.c,intent,self.source,'deploy');self.request('stop')
        with patch.object(control,'run') as process,patch.object(control.namespace,'paths',return_value={}):
            with self.assertRaises(ValueError):self.request('activate-support',intent=intent)
            process.assert_not_called()

    def test_failed_cancellation_readback_still_attempts_owned_stop_without_claiming_success(self):
        with patch.object(self.s,'halted',side_effect=OSError('inert original cancellation read failure')):
            with self.assertRaisesRegex(ValueError,'readback'):self.request('stop')
        self.assertEqual(self.stops,[True]);self.assertTrue(self.s.halted()['retired'])
        self.assertFalse(keys.permission(self.s,self.c)['enabled'])
        self.assertTrue(self.s.exists('signer-history.json'));self.assertTrue(self.s.exists('signer-original.cred'))

    def test_stop_preserves_host_conversion_fence_without_permanently_retiring_original_signer(self):
        self.s.stop(self.c,lambda:None,retire=True)
        self.assertFalse(keys.permission(self.s,self.c)['retired'])
        self.request('stop')
        self.assertTrue(self.s.halted()['retired']);self.assertFalse(keys.permission(self.s,self.c)['retired'])
        operation='e'*32
        self.s.authorize(self.c,operation,self.source,'deploy');self.s.begin(self.c,operation,lambda:None)
        self.s.publish(self.c,operation,{'units':{'target':self.target,'processes':{}}});self.s.consume(self.c,operation)
        keys.enable(self.s,self.c);self.assertTrue(keys.permission(self.s,self.c)['enabled'])
        self.request('destroy');self.assertTrue(keys.permission(self.s,self.c)['retired'])
        self.assertEqual(len(self.stops),2)

    def test_retirement_is_preserved_by_explicit_credential_restore(self):
        backup=keys.encrypted_backup(self.s,self.c);self.request('destroy')
        self.assertTrue(self.s.halted()['retired']);self.stops.clear()
        self.s.path('signer-original.cred').write_bytes(b'inert corrupt bytes')
        result=self.request('custody-restore',backup=backup)
        self.assertTrue(result['restored']);self.assertTrue(self.s.halted()['retired'])
        self.assertTrue(keys.permission(self.s,self.c)['retired']);self.assertFalse(result['signing_started'])

    def test_actual_boot_guard_exports_native_history_before_granting_a_signer_secret(self):
        keys.enable(self.s,self.c)
        known=copy.deepcopy(self.f.history_value)
        known['data'][0]['signed_blocks']=[{'slot':'90','signing_root':None}]
        control.history.observe(self.s,self.c,self.plan,'0x'+'1'*96,known)
        active=self.s.guard(self.c);qualified={'source':self.source,'target':self.target}
        with patch.object(control,'active',return_value=(active,qualified)),              patch.object(control.namespace,'paths',return_value={}),patch.object(control.layout,'capacity'),              patch.object(control,'quiescent'),patch.object(control.health,'wait_ready'),patch.object(control,'grant') as grant:
            # The native export fixture returns a well-formed but older history
            # on the SAME retained database inode; metadata alone cannot detect it.
            with self.assertRaisesRegex(ValueError,'regressed'):control.guard(self.s,self.c,control.units.UNITS[3])
            grant.assert_not_called()
        self.assertEqual(self.s.get('signer-import.json')['ever_authorized'],False)

    def test_signer_guard_refuses_definitions_or_keystore_of_another_owner_or_group(self):
        keys.enable(self.s,self.c);keys.guard(self.s,self.c);folder=self.f.data/'vc/validators'
        receipts={path.name:path.read_bytes() for path in self.s.directory.iterdir()};calls=len(self.f.calls)
        refused='managed file is indirect, shared, foreign or has unsafe permissions';group='original native definition group differs'
        account=tuple(self.plan['users']['ev-validator'].values())
        for name,value,message in [('validator_definitions.yml',(77,account[1]),refused),('validator_definitions.yml',(0,account[1]),refused),
                                   ('validator_definitions.yml',(account[0],77),group),('validator_definitions.yml',(account[0],0),group),
                                   ('original-keystore.json',account,refused),('original-keystore.json',(0,account[1]),group)]:
            with self.subTest(name=name,owner=value):
                info=(folder/name).stat();key=(info.st_dev,info.st_ino);owner=self.f.f.owners[key];self.f.f.owners[key]=value
                try:
                    with self.assertRaisesRegex(ValueError,message):keys.guard(self.s,self.c)
                finally:self.f.f.owners[key]=owner
                self.assertEqual({path.name:path.read_bytes() for path in self.s.directory.iterdir()},receipts)
                self.assertEqual(len(self.f.calls),calls)
        keys.guard(self.s,self.c);self.assertFalse(self.s.get('signer-import.json')['ever_authorized'])

    def test_actual_install_rotates_transport_files_before_cutover_publication(self):
        leaf={'certificate':'inert original certificate','private_key':'inert original private TLS key'}
        ca={'engine':'inert original engine CA','beacon':'inert original beacon CA'}
        def ready(_state,_expected,_purpose):return {},leaf
        with patch.object(control,'quiescent'),patch.object(control,'public_roots',return_value=b'inert OS public roots'),              patch.object(control.engine,'value',return_value=b'1'*64),patch.object(control.tls,'ready',side_effect=ready),              patch.object(control.tls,'certificate_authority',side_effect=lambda _s,_e,purpose:ca[purpose]):
            control.provision_transport(self.s,self.c)
            path=control.native.RUN/'beacon/server.key';self.assertEqual(path.read_bytes(),b'inert original private TLS key')
            operation='e'*32;self.s.authorize(self.c,operation,self.source,'update');self.s.begin(self.c,operation,lambda:None)
            leaf.update(certificate='inert renewed certificate',private_key='inert renewed private TLS key')
            ca.update(engine='inert renewed engine CA',beacon='inert renewed beacon CA')
            with patch.object(control.namespace,'paths',return_value={}),patch.object(control.namespace,'publish',return_value='a'*64),                  patch.object(control.layout,'capacity'),patch.object(control,'selected',return_value=self.target),                  patch.object(control.tls,'renew'),patch.object(control.health,'synchronized_clock'),                  patch.object(control.units,'process_receipt',return_value={'target':self.target}),                  patch.object(control.units,'publish'),patch.object(control,'run',return_value=b''):
                self.assertTrue(self.request('install',intent=operation)['installed'])
            self.assertTrue(self.s.exists('cutover.json'))
            self.assertEqual(path.read_bytes(),b'inert renewed private TLS key')
            self.s.publish(self.c,operation,self.s.get('installed-'+operation+'.json'))
            self.assertFalse(self.s.exists('cutover.json'))
            # The actual boot component now reads the identical completed grant;
            # it does not need to invent another stopped cutover for the new leaf.
            control.beacon_transport(self.s,self.c)
            self.assertEqual(path.read_bytes(),b'inert renewed private TLS key')

    def test_failed_start_checks_attempt_owned_stop_for_an_already_running_original_signer(self):
        keys.enable(self.s,self.c)
        with patch.object(control.namespace,'paths',return_value={}),patch.object(control,'status',return_value={'signer_active':True}),              patch.object(keys,'guard',side_effect=ValueError('inert original health failure')):
            with self.assertRaises(ValueError):self.request('start')
        self.assertEqual(self.stops,[True]);self.assertFalse(keys.permission(self.s,self.c)['enabled'])
        self.assertTrue(self.s.exists('signer-original.cred'));self.assertTrue(self.s.exists('signer-history.json'))

    def test_original_scope_handles_nss_drift_without_canceling_pending_work(self):
        operation='e'*32;self.s.authorize(self.c,operation,self.source,'update')
        with self.assertRaises(ValueError):self.request('start')
        self.assertEqual(self.stops,[]);self.assertEqual(self.s.current(self.c,operation)['intent'],operation)
        self.s.recover(self.c,operation,lambda:None)
        self.f.base.users['ev-validator'].pw_uid=777
        with self.assertRaises(ValueError):self.request('start')
        self.assertEqual(self.stops,[True]);self.assertEqual(self.f.base.users['ev-validator'].pw_uid,777)

    def test_public_deployment_excludes_units_and_private_material(self):
        value=self.request('deployment')
        self.assertEqual(set(value['active']),{'intent','generation','target'})
        self.assertEqual(set(value['source_floor']),{'reth','lighthouse'})
        self.assertNotIn('ciphertext',str(value));self.assertNotIn('material_sha256',str(value))


if __name__=='__main__':unittest.main()

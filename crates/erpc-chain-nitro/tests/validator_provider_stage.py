#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original controller/provider replacement with inert network and crypto only."""
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import validator_wallet_stage as wallet_fixture
import control
import credentials
import history
import host
import provider_stage
import storage


class Provider(unittest.TestCase):
    def setUp(self):
        self.fixture=wallet_fixture.Stage('runTest')
        if hasattr(self,'expected_override'):self.fixture.expected_override=self.expected_override
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.control=self.fixture.control;self.expected=self.fixture.expected
        self.events=self.fixture.events
        patch.object(host,'UPSTREAM_CUSTODY',self.fixture.history.root/'providers').start()
        def client(config):
            if config!={'public_fixture':'replacement provider'}:raise ValueError('inert invalid provider')
            return SimpleNamespace(verify=lambda:self.events.append('candidate chain and beacon'))
        patch.object(credentials,'client',side_effect=client).start()
        patch.object(control.Control,'provider_observation',side_effect=lambda *_:self.events.append('candidate protocol')).start()
        def observation(instance):
            credentials.inspect(instance.state,instance.expected)
            return {'funding_checks_passed':True,'is_staked':False}
        patch.object(control.Control,'parent_observation',observation).start()
        self.raw=json.dumps({'public_fixture':'replacement provider'})
        self.token='e'*32

    def query(self,action,**fields):return dict(action=action,contract=self.expected,intent=self.token,**fields)
    def authorize(self):return control.dispatch(self.query('provider-stage-authorize'))
    def deliver(self):return control.dispatch(self.query('provider-stage-import',secret=self.raw))
    def active(self):
        # Establish the already-reviewed original wallet/history fixture without
        # any real provider connection. Subsequent recovery uses real inspection.
        with patch.object(control.Control,'parent_observation',return_value={'funding_checks_passed':True,'is_staked':False}):
            original=self.fixture.first_active()
        self.control.state.activate(self.expected,'f'*32,lambda _:None)
        self.fixture.running=True
        return original

    def test_active_missing_provider_recovers_before_prepare_preserving_wallet_history_and_ca(self):
        original=self.active()
        key=(host.CUSTODY/'wallet.cred').read_bytes()
        ca=self.fixture.history.root/'local-ca';ca.write_bytes(b'inert original private CA')
        with self.assertRaises(FileNotFoundError):self.control.parent_observation()
        self.events.clear();value=self.authorize()
        self.assertTrue(value['requires_import']);self.assertFalse(self.fixture.running)
        self.assertEqual(self.fixture.ciphers[key],self.fixture.raw)
        self.assertTrue(self.deliver()['upstreams_verified'])
        self.assertLess(self.events.index('owned drain'),self.events.index('candidate chain and beacon'))
        self.assertLess(self.events.index('candidate protocol'),self.events.index('cipher encrypt'))
        self.assertTrue(self.control.state.fence()['stopped'])
        self.control.prepare('a'*32,dict(self.fixture.target,phase='active'))
        self.assertEqual(self.control.state.get('signer-activated.json')['origin'],original['origin'])
        self.assertEqual((host.CUSTODY/'wallet.cred').read_bytes(),key);self.assertEqual(ca.read_bytes(),b'inert original private CA')

    def test_observer_recovery_does_not_read_or_install_wallet(self):
        self.authorize();self.deliver()
        self.assertFalse((host.ROOT/'key-origin.json').exists())
        self.assertFalse((host.ROOT/'signer-activated.json').exists())
        self.control.prepare('a'*32,self.fixture.target)
        self.assertFalse(self.fixture.running)

    def test_stale_permission_after_stop_or_other_recovery_cannot_read_or_replace_provider(self):
        self.authorize()
        for supersede in (lambda:self.control.stop(),lambda:provider_stage.authorize(self.control,'b'*32)):
            self.authorize();supersede();before=dict(self.fixture.ciphers)
            with self.assertRaises(ValueError):self.deliver()
            self.assertEqual(self.fixture.ciphers,before)
        self.authorize();self.deliver()

    def test_late_nss_history_or_foreign_scope_refuses_before_secret_transform(self):
        self.active();self.authorize();before=dict(self.fixture.ciphers)
        with patch.object(control.accounts,'verify',side_effect=ValueError('inert original NSS drift')):
            with self.assertRaises(ValueError):self.deliver()
        self.assertEqual(self.fixture.ciphers,before)
        foreign=dict(self.expected,owner='z'*26)
        with self.assertRaises(ValueError):control.dispatch(dict(self.query('provider-stage-import',secret=self.raw),contract=foreign))
        path=host.DATA/'chain/nodekey';original=path.read_bytes();path.write_bytes(b'inert foreign key')
        with self.assertRaises(ValueError):self.deliver()
        self.assertEqual(self.fixture.ciphers,before);path.write_bytes(original)
        self.deliver()

    def test_invalid_candidate_keeps_existing_cipher_and_original_stopped(self):
        self.authorize();self.deliver();old=(host.UPSTREAM_CUSTODY/'upstreams.cred').read_bytes()
        self.token='a'*32;self.authorize()
        with self.assertRaises(ValueError):control.dispatch(self.query('provider-stage-import',secret='{}'))
        with patch.object(control.Control,'provider_observation',side_effect=ValueError('inert wrong protocol')):
            with self.assertRaises(ValueError):self.deliver()
        self.assertEqual((host.UPSTREAM_CUSTODY/'upstreams.cred').read_bytes(),old)
        self.assertTrue(self.control.state.fence()['stopped']);self.assertFalse(self.fixture.running)

    def test_public_authorization_barrier_failure_never_delivers_and_retry_recovers(self):
        self.active();original=os.fsync
        def fail(fd):
            if os.fstat(fd).st_ino==host.ROOT.stat().st_ino:raise OSError('inert root barrier failure')
            return original(fd)
        before=dict(self.fixture.ciphers)
        with patch.object(os,'fsync',side_effect=fail):
            for _ in range(2):
                with self.assertRaises((OSError,ValueError)):self.authorize()
                self.assertFalse(self.fixture.running)
        self.assertEqual(self.fixture.ciphers,before)
        self.authorize();self.deliver()

    def test_partial_provider_receipt_publication_reuses_encrypted_candidate_after_retry(self):
        self.authorize();original=self.control.state.put
        def fail(name,value):
            if name=='upstreams.json':raise OSError('inert receipt publication failure')
            return original(name,value)
        with patch.object(control.State,'put',lambda state,name,value:fail(name,value)):
            with self.assertRaises(OSError):self.deliver()
        cipher=(host.UPSTREAM_CUSTODY/'upstreams.cred').read_bytes()
        self.assertTrue(self.control.state.fence()['stopped']);self.assertFalse(self.fixture.running)
        self.deliver();self.assertEqual((host.UPSTREAM_CUSTODY/'upstreams.cred').read_bytes(),cipher)
        self.assertEqual(credentials.inspect(self.control.state,self.expected),json.loads(self.raw))


class Barriers(unittest.TestCase):
    def run_case(self,point=None):
        fixture=Provider('runTest');fixture.setUp()
        try:
            original=fixture.active();fixture.authorize()
            raw_key=(host.CUSTODY/'wallet.cred').read_bytes()
            data={str(path.relative_to(host.DATA)):path.read_bytes() for path in host.DATA.rglob('*') if path.is_file()}
            count=0;sync=os.fsync
            def barrier(fd):
                nonlocal count
                count+=1
                if count==point:raise OSError('inert selected publication barrier')
                return sync(fd)
            with patch.object(os,'fsync',side_effect=barrier):
                if point is None:fixture.deliver()
                else:
                    with self.assertRaises(OSError):fixture.deliver()
            if point is not None:
                self.assertEqual(count,point)
                self.assertTrue(fixture.control.state.fence()['stopped']);self.assertFalse(fixture.fixture.running)
                fixture.deliver()
            self.assertEqual((host.CUSTODY/'wallet.cred').read_bytes(),raw_key)
            self.assertEqual(fixture.control.state.get('signer-activated.json')['origin'],original['origin'])
            self.assertEqual({str(path.relative_to(host.DATA)):path.read_bytes() for path in host.DATA.rglob('*') if path.is_file()},data)
            self.assertEqual(credentials.inspect(fixture.control.state,fixture.expected),json.loads(fixture.raw))
            return count
        finally:fixture.doCleanups()

    def test_each_actual_private_publication_fsync_failure_stays_stopped_and_retry_retains_original(self):
        total=self.run_case();self.assertGreaterEqual(total,10)
        for point in range(1,total+1):
            with self.subTest(point=point):self.run_case(point)


if __name__=='__main__':unittest.main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual controller/custody/history order with real files and inert OS/crypto.

The scalar-one public test encoding is never used to sign or generate a key.
Only original NSS, native observations, systemd and encryption are modeled.
"""
from pathlib import Path
import hashlib
import os
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
from validator_history import History
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'erpc-chain-rollup/templates/scripts'))
import control
import custody
import history
import host
import installer
import protocol
import publication
import storage
import wallet_stage


class Stage(unittest.TestCase):
    def setUp(self):
        self.history=History('runTest')
        if hasattr(self,'expected_override'):self.history.expected_override=self.expected_override
        self.history.setUp();self.addCleanup(self.history.doCleanups)
        self.expected=self.history.expected;self.records={'node':self.history.account,'transport':{'uid':os.getuid()+1,'gid':os.getgid()+1}}
        patch.object(host,'RUNTIME',self.history.root/'runtime').start()
        patch.object(host,'CUSTODY',self.history.root/'custody').start()
        storage.directory(host.RUNTIME,create=True)
        self.control=control.Control(self.expected,run=host.command)
        self.target={'phase':'observing','version':protocol.VERSION,'commit':protocol.COMMIT,
                     'image':protocol.IMAGE,'image_id':protocol.IMAGE_ID,'helpers_sha256':'a'*64,'config_id':'b'*64}
        self.events=[];self.running=False;self.ciphers={}
        self.raw=b'0'*63+b'1'
        patch.object(host,'namespaces',side_effect=lambda:self.events.append('namespace')).start()
        patch.object(host,'capacity').start()
        patch.object(control.accounts,'verify',side_effect=lambda *_:(self.events.append('nss') or self.records)).start()
        patch.object(control.accounts,'retained',return_value=self.records).start()
        patch.object(control.container,'image').start()
        patch.object(publication,'verify').start()
        patch.object(control.services,'transport').start()
        patch.object(control.services,'running').start()
        def prove(*args,**kwargs):
            if not self.running:raise ValueError('inert original observer stopped')
            return {'inert':'original native PID'}
        patch.object(control.container,'prove',side_effect=prove).start()
        patch.object(publication,'profile',return_value=('a'*64,{})).start()
        patch.object(control.authority,'revoke',side_effect=lambda *_:self.events.append('revoke')).start()
        patch.object(custody,'clear_runtime',side_effect=lambda *_:self.events.append('remove runtime')).start()
        patch.object(custody,'stage_runtime',side_effect=AssertionError('observer must never receive wallet material')).start()
        patch.object(control.authority,'grant',side_effect=AssertionError('staging must not grant sending')).start()
        def stop(*args,**kwargs):self.events.append('owned drain');self.running=False
        patch.object(control.services,'shutdown',side_effect=stop).start()
        def quiet(*args,**kwargs):
            if self.running:raise ValueError('inert original writer still running')
        patch.object(control.processes,'quiescent',side_effect=quiet).start()
        def observe(_control):
            self.events.append('healthy observer')
            if not self.running:raise ValueError('inert observer is stopped')
            _control.state.guard(self.expected)
            return self.history.observed
        patch.object(control.Control,'observe',observe).start()
        patch.object(control.Control,'parent_observation',return_value={'funding_checks_passed':True,'is_staked':False}).start()
        patch.object(custody,'wallet',return_value=self.expected['wallet']).start()
        filesystem=host.command
        def transform(argv,**kwargs):
            if argv[0]=='/usr/bin/findmnt':return SimpleNamespace(returncode=0,stdout=filesystem(argv),stderr=b'')
            self.events.append('cipher '+argv[1]);value=kwargs['input']
            self.assertEqual(argv[0],'/usr/bin/systemd-creds')
            if argv[1]=='encrypt':
                out=('inert encrypted generation '+str(len(self.ciphers))).encode();self.ciphers[out]=value
            else:out=self.ciphers[value]
            return SimpleNamespace(returncode=0,stdout=out)
        patch.object(custody.subprocess,'run',side_effect=transform).start()
        self.control.prepare('d'*32,self.target)
        self.control.state.activate(self.expected,'d'*32,lambda _:None)
        self.running=True;self.observer_record();self.events.clear()

    def observer_record(self):
        self.control.state.put('container.json',{'contract':self.expected,'generation':self.control.state.fence()['generation'],
            'target':self.target,'account':self.records['node'],'container_id':'f'*64})

    def query(self,action,intent='e'*32,restore=False,**fields):
        return dict(action=action,contract=self.expected,intent=intent,restore=restore,**fields)

    def stage(self,restore=False,intent='e'*32):
        value=control.dispatch(self.query('wallet-stage-authorize',intent,restore))
        self.assertTrue(value['requires_import'])
        return control.dispatch(self.query('wallet-stage-import',intent,restore,secret=self.raw.decode()))

    def first_active(self):
        self.stage()
        self.control.prepare('f'*32,dict(self.target,phase='active'))
        return self.control.state.get('signer-activated.json')

    def test_first_original_cipher_stays_root_only_then_healthy_observer_drain_history_succeeds(self):
        self.assertFalse((host.ROOT/'key-origin.json').exists())
        self.assertTrue(self.stage()['original_verified'])
        self.assertTrue(self.running);self.assertNotIn('owned drain',self.events)
        self.assertLess(self.events.index('nss'),self.events.index('cipher encrypt'))
        self.assertEqual((host.CUSTODY/'wallet.cred').stat().st_mode&0o7777,0o600)
        self.assertFalse((host.RUNTIME/'wallet').exists())
        self.assertFalse((host.ROOT/'signer-activated.json').exists())
        self.events.clear()
        self.control.prepare('f'*32,dict(self.target,phase='active'))
        saved=self.control.state.get('signer-activated.json')
        self.assertEqual(saved['origin'],custody.origin(self.control.state,self.expected))
        self.assertEqual(saved['history'],history.current_history(self.control.state,self.expected,self.records['node']))
        self.assertLess(self.events.index('healthy observer'),self.events.index('owned drain'))
        self.assertFalse(self.running)

    def test_observing_firewall_phase_does_not_require_or_decrypt_wallet_custody(self):
        self.control.prepare('e'*32,self.target)
        query={'action':'prepare','contract':self.expected,'intent':'e'*32,'target':self.target}
        with patch.object(publication,'verify'),patch.object(installer.credentials,'inspect'),\
             patch.object(installer.crypto,'self_test'),patch.object(installer.parent_tls,'ensure'),\
             patch.object(custody,'inspect',side_effect=AssertionError('watchtower must not use the wallet')):
            value=installer.play(['play-before-firewall'],query,Path(control.__file__).parent)
        self.assertTrue(value['credentials_verified']);self.assertEqual(value['phase'],'observing')
        self.assertFalse((host.ROOT/'key-origin.json').exists());self.assertEqual(self.ciphers,{})

    def test_active_restore_drains_and_preserves_history_before_same_key_import(self):
        original=self.first_active();self.control.state.activate(self.expected,'f'*32,lambda _:None)
        self.running=True;(host.CUSTODY/'wallet.cred').unlink();self.events.clear()
        result=control.dispatch(self.query('wallet-stage-authorize',intent='a'*32,restore=True))
        self.assertTrue(result['requires_import']);self.assertFalse(self.running)
        self.assertTrue(self.control.state.fence()['stopped'])
        self.assertEqual(self.control.state.get('signer-activated.json')['origin'],original['origin'])
        self.assertNotIn('cipher encrypt',self.events)
        control.dispatch(self.query('wallet-stage-import',intent='a'*32,restore=True,secret=self.raw.decode()))
        self.assertLess(self.events.index('owned drain'),self.events.index('cipher encrypt'))
        self.assertFalse(self.running);self.assertTrue(self.control.state.fence()['stopped'])
        self.control.prepare('b'*32,dict(self.target,phase='active'))
        self.assertEqual(self.control.state.get('signer-activated.json')['origin'],original['origin'])

    def test_original_nss_namespace_stop_and_history_errors_prevent_private_transformation(self):
        for owner,name in [(host,'namespaces'),(control.accounts,'verify')]:
            with patch.object(owner,name,side_effect=ValueError('inert original authority drift')):
                with self.assertRaises(ValueError):control.dispatch(self.query('wallet-stage-authorize'))
            self.assertEqual(self.ciphers,{})
        self.first_active();self.control.state.activate(self.expected,'f'*32,lambda _:None)
        self.running=True;before=len(self.ciphers)
        with patch.object(control.services,'shutdown',side_effect=ValueError('inert retained writer')):
            with self.assertRaises(ValueError):control.dispatch(self.query('wallet-stage-authorize',restore=True))
        self.assertEqual(len(self.ciphers),before)
        self.running=False
        original=host.DATA/'chain/nodekey';raw=original.read_bytes();original.write_bytes(b'inert replaced node identity')
        with self.assertRaises(ValueError):control.dispatch(self.query('wallet-stage-authorize',restore=True))
        self.assertEqual(len(self.ciphers),before);original.write_bytes(raw)

    def test_private_stage_rechecks_original_nss_and_key_after_public_authorization(self):
        control.dispatch(self.query('wallet-stage-authorize'))
        for owner,name in [(host,'namespaces'),(control.accounts,'verify')]:
            with patch.object(owner,name,side_effect=ValueError('inert late original authority drift')):
                with self.assertRaises(ValueError):control.dispatch(self.query('wallet-stage-import',secret=self.raw.decode()))
            self.assertEqual(self.ciphers,{})
        with patch.object(custody,'wallet',return_value='0x'+'2'*40),self.assertRaises(ValueError):
            control.dispatch(self.query('wallet-stage-import',secret=self.raw.decode()))
        self.assertFalse((host.ROOT/'key-origin.json').exists());self.assertEqual(self.ciphers,{})

    def test_public_authorization_directory_failure_does_not_copy_a_key_and_retry_recovers(self):
        original=os.fsync
        def fail(descriptor):
            if os.fstat(descriptor).st_ino==host.ROOT.stat().st_ino:raise OSError('inert original-stage directory barrier')
            return original(descriptor)
        with patch.object(os,'fsync',side_effect=fail):
            for _ in range(2):
                with self.assertRaises(OSError):control.dispatch(self.query('wallet-stage-authorize'))
                self.assertTrue(self.running);self.assertEqual(self.ciphers,{})
        self.stage();self.control.prepare('f'*32,dict(self.target,phase='active'))
        self.assertTrue((host.ROOT/'signer-activated.json').exists())

    def test_cancelled_or_superseded_authorization_never_receives_a_new_cipher(self):
        control.dispatch(self.query('wallet-stage-authorize'))
        self.control.stop();before=len(self.ciphers)
        with self.assertRaises(ValueError):control.dispatch(self.query('wallet-stage-import',secret=self.raw.decode()))
        self.assertEqual(len(self.ciphers),before)
        self.control.prepare('b'*32,self.target);self.control.state.activate(self.expected,'b'*32,lambda _:None);self.running=True;self.observer_record()
        control.dispatch(self.query('wallet-stage-authorize',intent='c'*32))
        with self.assertRaises(ValueError):control.dispatch(self.query('wallet-stage-import',secret=self.raw.decode()))
        control.dispatch(self.query('wallet-stage-import',intent='c'*32,secret=self.raw.decode()))
        self.assertTrue(self.running)

    def test_failed_first_history_barrier_can_recover_the_original_observer_without_demotion(self):
        self.stage()
        with patch.object(history,'sync_directory',side_effect=OSError('inert pre-history directory barrier')):
            with self.assertRaises(OSError):self.control.prepare('f'*32,dict(self.target,phase='active'))
        self.assertFalse(self.running);self.assertFalse((host.ROOT/'signer-activated.json').exists())
        result=control.dispatch(self.query('wallet-stage-authorize',intent='a'*32))
        self.assertTrue(result['observer_required']);self.assertFalse(result['requires_import'])
        self.control.prepare('b'*32,self.target)
        self.control.state.activate(self.expected,'b'*32,lambda _:None);self.running=True;self.observer_record()
        result=control.dispatch(self.query('wallet-stage-authorize',intent='c'*32))
        self.assertFalse(result['observer_required']);self.assertFalse(result['requires_import'])
        self.control.prepare('c'*32,dict(self.target,phase='active'))
        self.assertTrue((host.ROOT/'signer-activated.json').exists())
        with self.assertRaises(ValueError):self.control.prepare('d'*32,self.target)

    def test_interrupted_first_cipher_publication_retries_same_original_before_active_preparation(self):
        control.dispatch(self.query('wallet-stage-authorize'))
        original=storage.write
        def failed(path,*args,**kwargs):
            if path.name=='key-current.json':raise OSError('inert lost original receipt')
            return original(path,*args,**kwargs)
        # State.put resolves its module's writer; the host ciphertext/staging
        # files and original plaintext digest are real protected temp files.
        import state
        with patch.object(state,'write',side_effect=failed),self.assertRaises(OSError):
            control.dispatch(self.query('wallet-stage-import',secret=self.raw.decode()))
        self.assertTrue(self.running);self.assertFalse((host.ROOT/'signer-activated.json').exists())
        cipher=(host.CUSTODY/'wallet.cred').read_bytes();count=len(self.ciphers)
        control.dispatch(self.query('wallet-stage-import',secret=self.raw.decode()))
        self.assertEqual(len(self.ciphers),count);self.assertEqual((host.CUSTODY/'wallet.cred').read_bytes(),cipher)
        self.control.prepare('f'*32,dict(self.target,phase='active'))
        self.assertTrue((host.ROOT/'signer-activated.json').exists())


if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Stage)
    raise SystemExit(not unittest.TextTestRunner().run(suite).wasSuccessful())

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual activation/state/controller transitions with public account transcripts.

NSS, PID1, build artifacts and native derivation are inert. No operational key,
certificate, native process or external transaction is created or executed.
"""
import copy
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent))
import deployment as fixtures
import validator as public_fixtures
import native_activation as activation
import native_deployment as deploy
import native_runtime_control as control
import native_files as files
from native_custody import base58


class Activation(unittest.TestCase):
    def setUp(self):
        self.inner = fixtures.Cutover(); self.inner.setUp(); self.addCleanup(self.inner.doCleanups)
        self.inner.completed_candidate(); self.state = self.inner.state; self.contract = self.inner.contract
        candidate = self.state.get('candidate-' + self.inner.intent + '.json')
        candidate['files'] = {'solana-keygen': {'sha256':'d'*64, 'size':100}}
        self.state.put('candidate-' + self.inner.intent + '.json', candidate)
        self.inner.dispatch('begin-runtime')
        self.inner.dispatch('install-runtime', firewall={'run':'original','bundle':'e'*64})
        self.inner.dispatch('activate-runtime')
        self.original = self.state.get('active.json')
        self.intent = 'f'*32
        self.policy = {'network':self.contract['network'], 'identity':self.contract['identity_account'],
            'vote_account':self.contract['vote_account'], 'withdrawer':self.contract['authority_account'],
            'bls':base58(bytes([12])*48), 'commission':5}
        self.request = {'action':'authorize-validator', 'contract':self.contract, 'intent':self.intent,
                        'registration':self.policy, 'exclusive_identity':True}
        self.identity = {'public':self.contract['identity_account'], 'cipher_sha256':'e'*64, 'plaintext_sha256':'9'*64}
        patch.object(activation.custody, 'complete', side_effect=lambda *_: dict(self.identity)).start()
        patch.object(activation, 'sync_file', lambda p: files.sync_file(p, os.getuid())).start()
        patch.object(control, 'status', return_value={'rpc_ready':True, 'mode':'sync'}).start()
        self.proof_stop_patch = patch.object(activation.proof, 'stop')
        self.proof_stop_patch.start()
        self.public = public_fixtures.PublicRegistration(); self.public.setUp()
        self.public.expected = self.policy
        self.public.genesis = json.loads(self.inner.raw)['networks'][self.contract['network']]['genesis']
        info = self.public.account['data']['parsed']['info']
        info.update(nodePubkey=self.policy['identity'], authorizedWithdrawer=self.policy['withdrawer'],
                    blsPubkeyCompressed=self.policy['bls'], authorizedVoters=[{'epoch':10,'authorizedVoter':self.policy['identity']}])
        observe = activation.validator.observe
        def observed(policy, genesis):
            self.public.epochs = 0
            return observe(policy, genesis, lambda _network, method, params: self.public.call('testnet',method,params), lambda:self.public.now)
        self.observation = patch.object(activation.validator, 'observe', side_effect=observed).start()

    def dispatch(self, action, **fields):
        return control.dispatch(self.state,self.contract,
            dict(action=action,contract=self.contract,intent=self.intent,**fields),self.inner.command)

    def authorize(self, **fields):
        return control.dispatch(self.state,self.contract,dict(self.request,**fields),self.inner.command)

    def evidence(self):
        pending, build = deploy.candidate(self.state,self.contract,self.intent)
        record = {'contract':self.contract,'intent':self.intent,'helper_revision':pending['target']['helper_revision'],
            'build_intent':pending['target']['build_intent'],'account':{'uid':20003,'gid':20003},
            'cipher_sha256':self.identity['cipher_sha256'],'unit_sha256':'7'*64,
            'keygen_sha256':build['files']['solana-keygen']['sha256']}
        self.state.put(activation.proof.RECEIPT,record)
        self.state.put('validator-proof-'+self.intent+'.json',dict(record,bls=self.policy['bls']))
        return record

    def install(self):
        return self.dispatch('install-runtime',firewall={'run':'activated','bundle':'6'*64})

    def test_actual_transition_reuses_original_build_and_binds_public_registration_and_native_proof(self):
        halt = self.state.halt(); result = self.authorize()
        self.assertEqual(result['target']['build_intent'],self.original['receipt']['build']['request']['intent'])
        self.assertEqual(self.state.get('active.json'),self.original); self.assertEqual(self.state.halt(),halt)
        self.dispatch('begin-runtime'); self.evidence(); self.install()
        self.assertTrue(self.dispatch('activate-runtime')['runtime_started'])
        active = self.state.guard(self.contract)
        self.assertEqual(active['receipt']['mode'],'validator')
        self.assertEqual(active['receipt']['build'],self.original['receipt']['build'])
        record, reference = activation.approved(self.state,self.contract,active['receipt']['validator'])
        self.assertEqual(record['registration'],self.policy)
        self.assertTrue(activation.qualify(self.state,self.contract,reference,self.public.genesis)['registration_verified'])
        self.assertEqual((self.state.directory/'retained-history').read_text(),'keep original native history')
        self.assertFalse(any('send' in method.lower() for method,_ in self.public.calls))

    def test_missing_consent_wrong_contract_unhealthy_sync_and_future_voter_refuse_before_authorization(self):
        for fields in ({'exclusive_identity':False}, {'registration':dict(self.policy,identity='5'*44)}):
            with self.assertRaises(ValueError):self.authorize(**fields)
        with patch.object(control,'status',return_value={'rpc_ready':False,'mode':'sync'}),self.assertRaises(ValueError):self.authorize()
        self.public.account['data']['parsed']['info']['authorizedVoters'].append({'epoch':12,'authorizedVoter':self.policy['withdrawer']})
        with self.assertRaises(ValueError):self.authorize()
        self.assertFalse((self.state.directory/'pending.json').exists());self.assertEqual(self.state.get('active.json'),self.original)

    def test_request_inputs_are_immutable_and_stopped_intent_never_resumes(self):
        self.authorize()
        with self.assertRaises(ValueError):self.authorize(registration=dict(self.policy,commission=6))
        self.state.stop(self.contract,lambda:None)
        with self.assertRaises(ValueError):self.authorize()
        with self.assertRaises(ValueError):self.dispatch('begin-runtime')
        self.assertFalse((self.state.directory/activation.RECORD).exists())

    def test_public_binding_is_reobserved_before_stopping_original_sync(self):
        self.authorize(); self.inner.calls.clear()
        self.public.account['data']['parsed']['info']['blsPubkeyCompressed']=base58(bytes([13])*48)
        with self.assertRaises(ValueError):self.dispatch('begin-runtime')
        self.assertFalse((self.state.directory/'cutover.json').exists())
        self.assertFalse(any(call[0]=='stop' for call in self.inner.calls))

    def test_missing_mismatched_or_foreign_completed_proof_never_publishes_voting_authority(self):
        self.authorize();self.dispatch('begin-runtime')
        with self.assertRaises(FileNotFoundError):self.install()
        record=self.evidence()
        for key,value in [('bls',base58(bytes([13])*48)),('cipher_sha256','1'*64),('keygen_sha256','2'*64),('intent','3'*32)]:
            bad=dict(record,bls=self.policy['bls']);bad[key]=value
            self.state.put('validator-proof-'+self.intent+'.json',bad)
            with self.subTest(key=key),self.assertRaises(ValueError):self.install()
            self.assertFalse((self.state.directory/activation.RECORD).exists())
        self.assertEqual(self.state.get('active.json'),self.original)

    def test_visible_activation_receipt_failure_retries_same_proof_and_preserves_runtime_fence(self):
        self.authorize();self.dispatch('begin-runtime');self.evidence()
        real=self.state.put
        def fail(name,value):
            real(name,value)
            if name==activation.RECORD:raise OSError('inert visible receipt failure')
        with patch.object(self.state,'put',side_effect=fail),self.assertRaises(OSError):self.install()
        self.assertTrue((self.state.directory/'cutover.json').exists());self.assertEqual(self.state.get('active.json'),self.original)
        original=(self.state.directory/activation.RECORD).read_bytes()
        self.authorize();self.install()
        self.assertEqual((self.state.directory/activation.RECORD).read_bytes(),original)

    def test_lost_reply_after_runtime_publication_resumes_exact_original_without_new_cutover_or_key(self):
        self.authorize();self.dispatch('begin-runtime');self.evidence();self.install()
        installed=self.state.get('runtime-install.json')
        self.state.publish(self.contract,self.intent,installed['receipt'])
        self.assertTrue(self.authorize()['runtime_published'])
        self.assertTrue(self.dispatch('activate-runtime')['runtime_started'])
        self.assertFalse((self.state.directory/'pending.json').exists())
        self.assertFalse((self.state.directory/'cutover.json').exists())
        with self.assertRaises(ValueError):self.authorize()

    def test_approved_key_restoration_keeps_same_plaintext_and_cannot_accept_other_proof_or_key(self):
        self.authorize();self.dispatch('begin-runtime');self.evidence();self.install()
        reference=self.state.get('runtime-install.json')['receipt']['validator']
        self.identity['cipher_sha256']='8'*64
        activation.approved(self.state,self.contract,reference)
        with self.assertRaises(ValueError):activation.approved(self.state,self.contract,dict(reference,sha256='0'*64))
        self.identity['plaintext_sha256']='0'*64
        with self.assertRaises(ValueError):activation.approved(self.state,self.contract,reference)

    def test_active_update_can_prepare_original_restoration_but_cannot_install_missing_custody(self):
        self.authorize();self.dispatch('begin-runtime');self.evidence();self.install();self.dispatch('activate-runtime')
        self.intent='6'*32
        request={'action':'authorize-build','contract':self.contract,'intent':self.intent,'operation':'update-config',
                 'mode':'validator','identity':self.contract['identity_account']}
        with patch.object(activation.custody,'complete',side_effect=ValueError('inert missing ciphertext')):
            result=control.dispatch(self.state,self.contract,request,self.inner.command)
            self.assertEqual(result['target']['mode'],'validator')
            self.dispatch('begin-runtime')
            with self.assertRaises(ValueError):self.install()
        self.install();self.assertTrue(self.dispatch('activate-runtime')['runtime_started'])
        self.assertEqual(self.state.guard(self.contract)['receipt']['validator']['intent'],'f'*32)

    def test_recovered_unstarted_activation_redeploys_sync_then_reuses_original_registration(self):
        self.authorize();self.dispatch('begin-runtime');self.evidence();self.install()
        original=(self.state.directory/activation.RECORD).read_bytes()
        self.dispatch('recover-cutover')
        self.inner.intent='6'*32;self.inner.request=dict(self.inner.request,intent=self.inner.intent)
        with patch.object(activation.custody,'complete',return_value={'public':'5'*44,'cipher_sha256':'e'*64}):
            self.inner.completed_candidate();self.inner.dispatch('begin-runtime')
            self.inner.dispatch('install-runtime',firewall={'run':'recovered','bundle':'3'*64})
            self.inner.dispatch('activate-runtime')
        # The inert replacement build supplies the same qualified tool identity.
        active=self.state.get('active.json');active['receipt']['build']['files']={'solana-keygen':{'sha256':'d'*64,'size':100}}
        self.state.put('active.json',active)
        self.intent='7'*32;self.request=dict(self.request,intent=self.intent)
        self.authorize();self.dispatch('begin-runtime');self.evidence();self.install()
        self.assertEqual((self.state.directory/activation.RECORD).read_bytes(),original)
        self.assertTrue(self.dispatch('activate-runtime')['runtime_started'])


if __name__=='__main__':unittest.main()

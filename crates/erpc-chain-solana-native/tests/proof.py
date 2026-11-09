# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual proof receipts and unit orchestration; native keygen/PID1 are inert."""
import hashlib
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import deployment as fixtures
import native_proof as proof
import native_files as files
from native_custody import base58


class Proof(unittest.TestCase):
    def setUp(self):
        self.inner=fixtures.Cutover();self.inner.setUp();self.addCleanup(self.inner.doCleanups)
        self.inner.completed_candidate();self.state=self.inner.state;self.contract=self.inner.contract;self.intent=self.inner.intent
        pending=self.state.get('pending.json');pending['action']='activate-validator'
        pending['target'].update(mode='validator',identity=self.contract['identity_account'])
        self.state.put('pending.json',pending);self.state.begin(self.contract,self.intent,lambda:None)
        candidate=self.state.get('candidate-'+self.intent+'.json')
        candidate['files']={'solana-keygen':{'size':100,'sha256':'d'*64}};self.state.put('candidate-'+self.intent+'.json',candidate)
        self.identity={'public':self.contract['identity_account'],'cipher_sha256':'e'*64,'plaintext_sha256':hashlib.sha256(b'inert identity input').hexdigest()}
        self.custody=patch.object(proof.custody,'complete',return_value=self.identity);self.custody.start();self.addCleanup(self.custody.stop)
        patch.object(proof,'OUTPUT',self.state.directory).start()
        patch.object(proof,'CREDENTIAL',self.inner.root/'credentials/proof/identity').start()
        patch.object(proof,'root_directory',lambda *args,**kwargs:None).start()
        patch.object(proof,'read',lambda p,size=1048576,owner=0:files.read(p,size,os.getuid())).start()
        patch.object(proof,'sync_file',lambda p:files.sync_file(p,os.getuid())).start()
        self.quiet=patch.object(proof.processes,'assert_quiescent').start()
        self.public=base58(bytes([12])*48);self.calls=[];self.skipped=False;self.bad_output=False

    def command(self,args,**kwargs):
        self.calls.append(args)
        if args[0]=='show':
            if args[-2:]==['--property=LoadState','--value']:return 'not-found\n'
            return ''.join(k+'='+v+'\n' for k,v in {'LoadState':'loaded','FragmentPath':str(proof.runtime.UNITS/proof.UNIT),
                'DropInPaths':'','User':'20003','Group':'20003','NeedDaemonReload':'no','MainPID':'0',
                'ActiveState':'inactive','Result':'exec-condition' if self.skipped else 'success','ExecMainStatus':'0'}.items())
        if args[0]=='start':
            path=proof.OUTPUT/('bls-public-'+self.intent+'.txt')
            path.write_text('unexpected native output' if self.bad_output else self.public+'\n');path.chmod(0o600)
        return ''

    def derive(self):return proof.derive(self.state,self.contract,self.intent,self.command)

    def test_only_public_output_is_captured_under_original_isolated_numeric_recipient(self):
        result=self.derive();self.assertEqual(result['bls'],self.public)
        unit=(proof.runtime.UNITS/proof.UNIT).read_text()
        for setting in ('User=20003\nGroup=20003','PrivateNetwork=true','RestrictAddressFamilies=AF_UNIX',
                        'StandardError=null','LimitFSIZE=4096','LoadCredentialEncrypted=identity:',
                        ' bls_pubkey '+str(proof.CREDENTIAL),'ExecCondition=+'):
            self.assertIn(setting,unit)
        self.assertNotIn('Environment=PRIVATE',unit)
        self.assertEqual(self.calls[-1],['stop',proof.UNIT])
        self.assertEqual(self.state.get('validator-proof-'+self.intent+'.json'),result)
        self.assertTrue((self.state.directory/'cutover.json').exists())

    def test_stale_cutover_never_materializes_or_starts_a_new_proof(self):
        self.state.stop(self.contract,lambda:None)
        with self.assertRaises(ValueError):self.derive()
        self.assertEqual(self.calls,[])
        self.assertFalse((proof.runtime.UNITS/proof.UNIT).exists())

    def test_skipped_condition_or_malformed_native_output_cannot_become_proof(self):
        self.skipped=True
        with self.assertRaises(ValueError):self.derive()
        self.assertFalse((self.state.directory/('validator-proof-'+self.intent+'.json')).exists())
        self.skipped=False;self.bad_output=True
        with self.assertRaises(ValueError):self.derive()
        self.assertFalse((self.state.directory/('validator-proof-'+self.intent+'.json')).exists())
        self.assertEqual(self.calls[-1],['stop',proof.UNIT])

    def test_unknown_output_or_modified_owned_unit_is_never_overwritten(self):
        path=proof.OUTPUT/('bls-public-'+self.intent+'.txt');outside=self.inner.root/'retain';outside.write_bytes(b'unrelated bytes')
        path.symlink_to(outside)
        with self.assertRaises((ValueError,FileNotFoundError)):self.derive()
        self.assertEqual(outside.read_bytes(),b'unrelated bytes');path.unlink()
        self.derive();unit=proof.runtime.UNITS/proof.UNIT;unit.write_text('unmanaged replacement')
        self.calls.clear()
        with self.assertRaises(ValueError):self.derive()
        self.assertEqual(unit.read_text(),'unmanaged replacement')
        self.assertFalse(any(call[0] in ('start','stop') for call in self.calls))

    def test_missing_or_different_original_cipher_does_not_start_a_proof(self):
        self.custody.stop()
        with patch.object(proof.custody,'complete',side_effect=ValueError('inert missing original ciphertext')):
            with self.assertRaises(ValueError):self.derive()
        self.assertFalse(any(call[0]=='start' for call in self.calls))


if __name__=='__main__':unittest.main()

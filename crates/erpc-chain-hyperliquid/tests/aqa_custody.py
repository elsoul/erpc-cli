# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert original-key vectors and mocked encryption; no host credentials or keys."""
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parents[1]/'templates/aqa'))
import erpc_aqa_common as common
import erpc_aqa_state as states
import erpc_aqa_custody as custody


class Custody(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name).resolve()
        self.contract={'network':'testnet','identity':{'agent_public_key':'04'+'11'*64}}
        self.state=states.State(self.root);self.state.put('owner.json',{'contract':self.contract})
        self.state.put('accounts.json',{'inert':'original account'})
        self.raw=json.dumps({'key':'01'*32}).encode();self.stops=[];self.argv=[]
        self.patches=[]
        def install(obj,name,value):
            p=patch.object(obj,name,value);p.start();self.patches.append(p)
        self.addCleanup(lambda:[p.stop() for p in reversed(self.patches)])
        install(custody,'ROOT',self.root);install(custody,'CREDENTIALS',self.root/'credentials')
        install(custody,'ACTIVE',custody.CREDENTIALS/'agent.cred')
        install(custody,'DECRYPTED',self.root/'runtime/.env')
        install(states,'read',lambda path:common.read(path,owner=os.getuid()))
        install(custody,'read',lambda path,limit=1048576:common.read(path,limit,owner=os.getuid()))
        install(custody.accounts,'accounts',lambda value:value)
        def directory(path,create=False):
            if create:path.mkdir(mode=0o700,parents=True,exist_ok=True)
            if path.is_symlink() or not path.is_dir() or path.stat().st_mode&0o022:raise ValueError('inert untrusted directory')
        install(custody,'owned_directory',directory)
        original=Path.lstat
        def metadata(path,*a,**kw):
            row=list(original(path,*a,**kw));row[4]=0;return os.stat_result(row)
        install(Path,'lstat',metadata)
        self.encryptions=0
        def execute(argv,input_data=None):
            self.argv.append([str(item) for item in argv])
            if argv[0]=='/usr/bin/openssl':
                self.assertIsInstance(input_data,bytes)
                return types.SimpleNamespace(stdout=custody.PUBLIC_DER_PREFIX+bytes.fromhex(self.contract['identity']['agent_public_key']))
            if 'encrypt' in argv:
                self.encryptions+=1
                # Reversible inert framing exercises I/O, not cryptographic secrecy.
                Path(argv[-1]).write_bytes(b'inert-envelope:'+str(self.encryptions).encode()+b':'+input_data)
                return types.SimpleNamespace(stdout=b'')
            self.assertIn('decrypt',argv)
            return types.SimpleNamespace(stdout=Path(argv[-2]).read_bytes().split(b':',2)[2])
        install(custody,'execute',execute)

    def load(self,restore=False,raw=None):
        return custody.import_original(self.state,self.contract,self.raw if raw is None else raw,
                                       restore,True,lambda:self.stops.append('owned shutdown'))

    def test_exact_dotenv_is_encrypted_without_secret_in_any_argument(self):
        self.load();record=custody.identity(self.state,self.contract)
        expected=b'PUBLISHER_PRIVATE_KEY=0x'+b'01'*32+b'\nNETWORK=testnet\nRUST_LOG=off\n'
        self.assertEqual(record['dotenv_sha256'],common.digest(expected))
        self.assertEqual(record['original_sha256'],common.digest(self.raw))
        self.assertEqual(self.stops,['owned shutdown'])
        self.assertTrue(all(('01'*32) not in arg for argv in self.argv for arg in argv))
        self.assertTrue(any('--with-key=host' in argv and '--name=.env' in argv for argv in self.argv))
        self.assertFalse((self.root/'.env').exists())

    def test_original_only_restore_retains_a_separate_cipher_inode_and_remains_stopped(self):
        self.load();old=custody.ACTIVE.read_bytes();inode=custody.ACTIVE.stat().st_ino
        self.assertTrue(self.load(restore=True)['restored'])
        previous=custody.CREDENTIALS/('previous-'+common.digest(old)+'.cred')
        self.assertEqual(previous.read_bytes(),old)
        self.assertNotEqual(previous.stat().st_ino,custody.ACTIVE.stat().st_ino)
        self.assertNotEqual(inode,custody.ACTIVE.stat().st_ino)
        self.assertTrue((self.root/'stopped').exists())
        with self.assertRaises(ValueError):self.load(restore=True,raw=json.dumps({'key':'02'*32}).encode())

    def test_visible_receipt_after_failed_publication_needs_durable_original_on_retry(self):
        real=self.state.put
        def fail(name,value):
            real(name,value)
            if name=='agent-identity.json':raise OSError('inert owner-directory durability failure')
        with patch.object(self.state,'put',fail),self.assertRaises(OSError):self.load()
        self.assertFalse(custody.ACTIVE.exists());receipt=self.state.get('agent-identity.json')
        staged=custody.CREDENTIALS/receipt['pending'];self.assertTrue(staged.exists())
        with patch.object(custody,'synchronize',side_effect=OSError('inert persistent barrier failure')):
            with self.assertRaises(OSError):self.load()
        self.assertFalse(custody.ACTIVE.exists());self.assertTrue(staged.exists())
        self.load();self.assertEqual(self.encryptions,1)
        self.assertEqual(self.state.get('agent-identity.json'),receipt)

    def test_cancellation_storage_failure_still_attempts_shutdown_without_publishing_key(self):
        with patch.object(self.state,'put',side_effect=OSError('inert storage failure')),\
             patch.object(self.state,'marker',side_effect=OSError('inert storage failure')):
            with self.assertRaises(ValueError):self.load()
        self.assertEqual(self.stops,['owned shutdown']);self.assertEqual(self.encryptions,0)

    def test_foreign_scope_unowned_cipher_and_ambiguous_fields_never_reach_encrypt(self):
        with self.assertRaises(ValueError):custody.import_original(self.state,dict(self.contract,network='mainnet'),self.raw,False,True,lambda:None)
        for raw in [b'{"key":"invalid"}',b'{"key":"inert","key":"duplicate"}',b'{"key":"inert","other":1}']:
            with self.assertRaises(ValueError):self.load(raw=raw)
        custody.CREDENTIALS.mkdir();custody.ACTIVE.write_bytes(b'foreign ciphertext')
        with self.assertRaises(ValueError):self.load()
        self.assertEqual(self.encryptions,0);self.assertEqual(self.stops,[])

    def test_runtime_requires_exact_regular_dotenv_path_and_original_hash(self):
        self.load();record=custody.identity(self.state,self.contract)
        custody.DECRYPTED.parent.mkdir()
        raw=custody.material(self.raw,self.contract)
        custody.DECRYPTED.write_bytes(raw);custody.DECRYPTED.chmod(0o400)
        original=os.fstat
        def metadata(fd):
            value=list(original(fd));value[4]=0;return os.stat_result(value)
        with patch.object(os,'fstat',metadata):
            self.assertEqual(custody.runtime_bytes(record,995),raw)
            custody.DECRYPTED.chmod(0o600)
            with self.assertRaises(ValueError):custody.runtime_bytes(record,995)
            custody.DECRYPTED.chmod(0o400);custody.DECRYPTED.unlink()
            unrelated=self.root/'parent.env';unrelated.write_bytes(raw);custody.DECRYPTED.symlink_to(unrelated)
            with self.assertRaises(OSError):custody.runtime_bytes(record,995)


if __name__=='__main__':unittest.main()

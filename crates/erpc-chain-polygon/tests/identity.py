# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Synthetic native initialization; no client or real key generation."""
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

@unittest.skipUnless(os.name=='posix','remote Linux custody uses POSIX locks')
class Identity(unittest.TestCase):
    def setUp(self):
        import state,identity
        self.state_module,self.identity=state,identity
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        for path in ('etc/polygon','var/lib/polygon','opt/erpc','run'):(self.root/path).mkdir(parents=True)
        self.profile=json.loads((ROOT/'networks/amoy.json').read_text())
        self.expected=state.contract('amoy','i'*26,'x86_64',self.profile['bor_genesis_hash'],self.profile['heimdall_genesis']['sha256'])
        self.calls=[];self.fail=False
        self.state=state.State(self.root,self.command,usage=lambda:(2_000_000_000_000,0),owner=os.getuid(),proof=type('FixtureAuthority',(),{'initial':lambda self:None,'can_start':lambda self,*args:None,'unoccupied':lambda self:None,'quiescent':lambda self:None,'startable':lambda self,*args:None,'listener':lambda self,*args:('fixture',)})())
        import volume_fixture
        volume_fixture.attach(self,self.state)
        volume_fixture.bind(self.state,self.expected);self.state.path('/etc/polygon/preparing').touch()
    def command(self,args,**kwargs):
        self.calls.append(args)
        if args[0]=='heimdalld-fixture':
            self.assertNotIn('private-fixture',' '.join(args));self.assertEqual(set(kwargs['env']),{'PATH','HOME','LANG'})
            home=Path(args[args.index('--home')+1]);(home/'config').mkdir(parents=True,exist_ok=True);
            self.assertIn('memory',(home/'config/client.toml').read_text());(home/'data').mkdir()
            for name in ('node_key.json','priv_validator_key.json'):
                (home/'config'/name).write_text(json.dumps({'priv_key':{'type':'inert-native-fixture','value':'private-fixture'}}))
            (home/'data/priv_validator_state.json').write_text('{"height":"0","round":0,"step":0}')
        elif args[:2]==['systemd-creds','encrypt']:
            self.assertNotIn('private-fixture',' '.join(args))
            if self.fail:raise subprocess.CalledProcessError(1,args)
            Path(args[-1]).write_bytes(b'encrypted-fixture:'+kwargs['input'])
        elif args[:2]==['systemctl','show']:
            return subprocess.CompletedProcess(args,0,b'0' if '--property=MainPID' in args else b'not-found',b'')
        elif args[:2]==['systemctl','is-active']:
            return subprocess.CompletedProcess(args,0,b'inactive',b'')
        return subprocess.CompletedProcess(args,0,b'',b'')
    def initialize(self):
        def temporary(**kwargs):return tempfile.TemporaryDirectory(dir=self.root/'run')
        return self.identity.initialize(self.state,self.expected,Path('heimdalld-fixture'),self.profile,
            generate_bor=lambda:(b'private-fixture','a'*128),temporary=temporary)
    def test_atomic_publication_and_retry_keep_original_credentials_and_history(self):
        first=self.initialize();count=len([a for a in self.calls if a[0]=='heimdalld-fixture'])
        self.identity.home(self.state,self.expected,self.profile)
        history=self.root/'var/lib/polygon/heimdall/data/priv_validator_state.json'
        history.write_text('{"height":"100","round":2,"step":3}')
        self.assertEqual(self.initialize(),first)
        self.identity.home(self.state,self.expected,self.profile)
        self.assertEqual(json.loads(history.read_text())['height'],'100')
        self.assertEqual(len([a for a in self.calls if a[0]=='heimdalld-fixture']),count)
        self.assertFalse(list((self.root/'run').iterdir()))
        history.unlink()
        with self.assertRaises(ValueError):self.identity.home(self.state,self.expected,self.profile)
    def test_interrupted_durable_original_and_home_publication_never_regenerates(self):
        import host
        from unittest.mock import patch
        original=host.publish
        def interrupted(source,destination,**kwargs):
            original(source,destination,**kwargs)
            if destination.name=='original':raise OSError('inert interruption after durable identity publication')
        with patch.object(host,'publish',side_effect=interrupted):
            with self.assertRaises(OSError):self.initialize()
        receipt=self.state.read('/etc/credstore.encrypted/polygon/original/receipt.json')
        self.assertEqual(self.initialize(),receipt)
        self.assertEqual(len([args for args in self.calls if args[0]=='heimdalld-fixture']),1)
        def home_interrupted(source,destination,**kwargs):
            original(source,destination,**kwargs)
            if destination.name=='heimdall':raise OSError('inert interruption after durable native home publication')
        with patch.object(host,'publish',side_effect=home_interrupted):
            with self.assertRaises(OSError):self.identity.home(self.state,self.expected,self.profile)
        history=self.root/'var/lib/polygon/heimdall/data/priv_validator_state.json'
        history.write_text('{"height":"100","round":2,"step":3}')
        self.identity.home(self.state,self.expected,self.profile)
        self.assertEqual(json.loads(history.read_text())['height'],'100')
        self.assertEqual(self.state.read('/etc/credstore.encrypted/polygon/original/home-state.json')['state'],'initialized')

    def test_failed_encryption_publishes_nothing_and_no_orphan_state_is_adopted(self):
        self.fail=True
        with self.assertRaises(subprocess.CalledProcessError):self.initialize()
        parent=self.root/'etc/credstore.encrypted/polygon'
        self.assertFalse((parent/'original').exists());self.assertFalse((parent/'original.pending').exists())
        self.assertFalse(list((self.root/'run').iterdir()))
        self.state.write('/etc/polygon/activation.json',{'fixture':'prior activation'})
        with self.assertRaises(ValueError):self.initialize()
    def test_cross_inventory_or_missing_ciphertext_never_regenerates(self):
        self.initialize()
        with self.assertRaises(ValueError):self.identity.receipt(self.state,dict(self.expected,owner='j'*26))
        (self.root/'etc/credstore.encrypted/polygon/original/heimdall-validator-key.json').unlink()
        before=len(self.calls)
        with self.assertRaises((ValueError,OSError)):self.initialize()
        self.assertFalse(any(a[0]=='heimdalld-fixture' for a in self.calls[before:]))

    def test_validator_original_publication_binds_both_native_accounts_and_never_resets_history(self):
        self.expected=self.state_module.contract('amoy','i'*26,'x86_64',self.profile['bor_genesis_hash'],
            self.profile['heimdall_genesis']['sha256'],'validator','0x'+'ab'*20,'0x'+'cd'*20)
        # This case selects its fresh test role before native identity creation.
        saved=self.state.read('/etc/polygon/storage.json');saved['contract']=self.expected
        self.state.write('/etc/polygon/storage.json',saved)
        self.state.write('/etc/polygon/contract.json',dict(self.expected,runtime_protocol=3))
        public={'signer':self.expected['signer'],'public_key':'0x04'+'ab'*64}
        material={'bor-signer.json':b'inert-native-v3','bor-password':b'inert-password',
            'heimdall-validator-key.json':b'inert-native-filepv'}
        def initialize():return self.identity.initialize(self.state,self.expected,Path('heimdalld-fixture'),self.profile,
            generate_bor=lambda:(b'private-fixture','a'*128),
            temporary=lambda **kwargs:tempfile.TemporaryDirectory(dir=self.root/'run'),validator=(public,material))
        first=initialize()
        self.assertEqual(first['validator'],public)
        self.assertEqual(set(first['ciphertexts']),set(self.identity.files(self.expected)))
        self.identity.home(self.state,self.expected,self.profile)
        history=self.root/'var/lib/polygon/heimdall/data/priv_validator_state.json'
        history.write_text('{"height":"555","round":2,"step":3}')
        calls=len(self.calls)
        self.assertEqual(initialize(),first)
        self.assertFalse(any(call[0]=='heimdalld-fixture' for call in self.calls[calls:]))
        self.identity.home(self.state,self.expected,self.profile)
        self.assertEqual(json.loads(history.read_text())['height'],'555')
        (self.root/'etc/credstore.encrypted/polygon/original/bor-signer.json').unlink()
        with self.assertRaises((ValueError,OSError)):initialize()
        self.assertEqual(json.loads(history.read_text())['height'],'555')

    def test_rpc_cannot_import_signer_and_validator_requires_its_original_dedicated_identity(self):
        args=(self.state,self.expected,Path('heimdalld-fixture'),self.profile)
        with self.assertRaisesRegex(ValueError,'RPC identities cannot import'):
            self.identity.initialize(*args,validator=({'signer':'inert'},{}))
        self.expected=self.state_module.contract('amoy','i'*26,'x86_64',self.profile['bor_genesis_hash'],
            self.profile['heimdall_genesis']['sha256'],'validator','0x'+'ab'*20,'0x'+'cd'*20)
        # This case selects its fresh test role before native identity creation.
        saved=self.state.read('/etc/polygon/storage.json');saved['contract']=self.expected
        self.state.write('/etc/polygon/storage.json',saved)
        self.state.write('/etc/polygon/contract.json',dict(self.expected,runtime_protocol=3))
        with self.assertRaisesRegex(ValueError,'verified native hot-signer'):
            self.identity.initialize(self.state,self.expected,Path('heimdalld-fixture'),self.profile)
        self.assertTrue(all(call[0]=='systemctl' and call[1] in ('show','is-active') for call in self.calls))
        with self.assertRaisesRegex(ValueError,'must differ'):
            self.state_module.contract('amoy','i'*26,'x86_64',self.profile['bor_genesis_hash'],
                self.profile['heimdall_genesis']['sha256'],'validator','0x'+'ab'*20,'0x'+'ab'*20)

if __name__=='__main__':unittest.main()

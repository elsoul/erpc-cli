# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert native-import protocol fixtures: no clients, real keys or transactions."""
import base64
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))


@unittest.skipUnless(os.name=='posix','remote custody requires POSIX descriptors')
class Signer(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('polygon_signer',ROOT/'templates/scripts/signer.py')
        self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.raw=bytes([237])*32  # Inert protocol bytes; no native or cryptographic operation uses them.
        self.public=bytes([4])+bytes(range(64))
        self.address='0x'+'ab'*20
        self.profile={'network':'amoy','heimdall_chain_id':'heimdallv2-80002'}
        self.calls=[];self.native_failure=None;self.mismatch=False;self.tmpfs=True
        self.native_key={'address':self.address[2:].upper(),
            'pub_key':{'type':'cometbft/PubKeySecp256k1eth','value':base64.b64encode(self.public).decode()},
            'priv_key':{'type':'cometbft/PrivKeySecp256k1eth','value':base64.b64encode(self.raw).decode()}}
        self.keystore={'version':3,'address':self.address[2:],
            'crypto':{'cipher':'aes-128-ctr','ciphertext':'aa'*32,'mac':'bb'*32,
                'cipherparams':{'iv':'cc'*16},'kdf':'scrypt',
                'kdfparams':{'n':262144,'r':8,'p':1,'dklen':32,'salt':'dd'*32}}}
        outer=self
        class FixtureState:
            def protected(self,path):return outer.root
            def command(self,*args):
                outer.assertEqual(args,('/usr/bin/findmnt','--noheadings','--output','FSTYPE','--target','/run'))
                return subprocess.CompletedProcess(args,0,b'tmpfs\n' if outer.tmpfs else b'ext4\n',b'')
            def run(self,args,**options):return outer.native_run(args,**options)
        self.state=FixtureState()

    def native_run(self,args,**options):
        self.calls.append((args,options))
        self.assertEqual(args[:3],['/usr/bin/unshare','--net','--'])
        self.assertEqual(options['stdout'],subprocess.DEVNULL);self.assertEqual(options['stderr'],subprocess.DEVNULL)
        self.assertEqual(options['umask'],0o077)
        self.assertEqual(set(options['env']),{'PATH','HOME','LANG','TMPDIR'})
        self.assertNotIn(self.raw.hex(),' '.join(args)+str(options['env']))
        if self.native_failure is not None and self.native_failure in args:return subprocess.CompletedProcess(args,1,b'ignored fixture',b'ignored fixture')
        base=Path(options['cwd'])
        if 'init' in args:
            home=Path(args[args.index('--home')+1]);(home/'config/app.toml').write_text('fixture = true\n')
        else:
            fd=options['pass_fds'][0]
            self.assertIn('/proc/self/fd/'+str(fd),args)
            self.assertEqual(os.read(fd,100),self.raw.hex().encode())
            if 'import' in args:
                password=options['input']
                self.assertEqual(len(password),97);self.assertEqual(password[-1:],b'\n')
                self.assertNotIn(password[:-1].decode(),' '.join(args)+str(options['env']))
                directory=Path(args[args.index('--keystore')+1]);directory.mkdir(mode=0o700)
                output=directory/'inert-native-account';output.write_text(json.dumps(self.keystore));output.chmod(0o600)
            else:
                self.assertIn('import-validator-key',args);self.assertEqual(options['input'],b'')
                value=dict(self.native_key)
                if self.mismatch:value['address']='cd'*20
                output=base/'priv_validator_key.json';output.write_text(json.dumps(value));output.chmod(0o600)
        return subprocess.CompletedProcess(args,0,b'',b'')

    @contextmanager
    def descriptor(self,value):
        # macOS/Windows do not provide Linux memfd. This synthetic descriptor
        # tests inherited-position/argv behavior without actual secret material.
        with tempfile.TemporaryFile() as stream:
            stream.write(value);stream.seek(0);yield stream.fileno()

    def convert(self):
        return self.module.convert(self.state,self.profile,Path('inert-bor'),Path('inert-heimdall'),
            self.raw,self.address,'[custom]\nchain="amoy"\n',descriptor=self.descriptor,
            temporary=lambda **kwargs:tempfile.TemporaryDirectory(dir=self.root),derive=lambda value:self.public)

    def test_actual_conversion_protocol_uses_inherited_input_and_discards_private_home(self):
        public,material=self.convert()
        self.assertEqual(public,{'signer':self.address,'public_key':'0x'+self.public.hex()})
        self.assertEqual(set(material),set(self.module.FILES))
        self.assertEqual(material['bor-password']+b'\n',self.calls[1][1]['input'])
        self.assertEqual(len(self.calls),3)
        self.assertFalse(list(self.root.iterdir()))
        self.assertNotIn(self.raw.hex(),json.dumps(public))

    def test_failure_or_wrong_native_address_returns_no_partial_credentials(self):
        for failure in ('init','import','import-validator-key'):
            self.native_failure=failure
            with self.assertRaisesRegex(ValueError,'native conversion failed'):self.convert()
            self.assertFalse(list(self.root.iterdir()))
        self.native_failure=None;self.mismatch=True
        with self.assertRaisesRegex(ValueError,'dedicated signer'):self.convert()
        self.assertFalse(list(self.root.iterdir()))

    def test_non_tmpfs_refuses_before_any_native_execution(self):
        self.tmpfs=False
        with self.assertRaisesRegex(ValueError,'tmpfs'):self.convert()
        self.assertEqual(self.calls,[])

    def test_native_material_must_match_input_public_key_and_standard_scrypt(self):
        def check():return self.module.checked_material(self.raw,self.address,
            json.dumps(self.native_key).encode(),json.dumps(self.keystore).encode(),lambda value:self.public)
        check()
        self.native_key['priv_key']['value']=base64.b64encode(bytes([236])*32).decode()
        with self.assertRaisesRegex(ValueError,'conversion differs'):check()
        self.native_key['priv_key']['value']=base64.b64encode(self.raw).decode()
        self.keystore['crypto']['kdfparams']['n']=4096
        with self.assertRaisesRegex(ValueError,'standard scrypt'):check()
        self.keystore['crypto']['kdfparams']['n']=262144
        self.keystore['address']='cd'*20
        with self.assertRaisesRegex(ValueError,'Bor account differs'):check()

    def test_private_output_links_excess_mode_and_size_are_refused(self):
        output=self.root/'private-output';output.write_bytes(b'inert');output.chmod(0o600)
        self.assertEqual(self.module.bounded(output),b'inert')
        output.chmod(0o644)
        with self.assertRaises(ValueError):self.module.bounded(output)
        output.chmod(0o600);linked=self.root/'alias';os.link(output,linked)
        with self.assertRaises(ValueError):self.module.bounded(output)
        linked.unlink();output.write_bytes(b'x'*(self.module.MAX_FILE+1))
        with self.assertRaises(ValueError):self.module.bounded(output)

    def test_invalid_input_never_echoes_secret_or_accepts_non_scalar(self):
        for value in (None,'inert-invalid','0'*64,'f'*64):
            with self.assertRaises(ValueError) as error:self.module.secret_scalar(value)
            if isinstance(value,str):self.assertNotIn(value,str(error.exception))
        self.assertEqual(self.module.secret_scalar('0x'+self.raw.hex()),self.raw)

@unittest.skipUnless(os.name=='posix','host publication requires POSIX filesystem semantics')
class Staging(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('polygon_identity_staging',ROOT/'tests/identity.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.fixture=module.Identity();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.state=self.fixture.state;self.profile=self.fixture.profile
        spec=importlib.util.spec_from_file_location('polygon_signer_staging',ROOT/'templates/scripts/signer.py')
        self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)
        from types import SimpleNamespace
        self.state.accounts=SimpleNamespace(verify=lambda expected:{})
        self.expected=self.fixture.state_module.contract('amoy','i'*26,'x86_64',self.profile['bor_genesis_hash'],
            self.profile['heimdall_genesis']['sha256'],'validator','0x'+'ab'*20,'0x'+'cd'*20)
        self.profile['validator']={'phase':'observing','signer':self.expected['signer'],'sentries':[{'address':'192.0.2.2','bor_node_id':'ab'*64,'heimdall_node_id':'cd'*20}]}
        saved=self.state.read('/etc/polygon/storage.json');saved['contract']=self.expected
        self.state.write('/etc/polygon/storage.json',saved)
        self.state.write('/etc/polygon/contract.json',dict(self.expected,runtime_protocol=3))
        self.state.path('/etc/credstore.encrypted/polygon').mkdir(parents=True,mode=0o700)
        self.intent='a'*32;self.helpers='b'*64;self.raw=bytes([237])*32
        self.public=bytes([4])+bytes(range(64))
        self.state.prepare(self.expected,self.intent,self.profile,self.helpers)
    def stage(self,raw=None,derive=None):
        return self.module.stage(self.state,self.expected,self.intent,self.profile,self.helpers,
            (raw or self.raw).hex(),derive=derive or (lambda value:self.public),identify=lambda point:self.expected['signer'])
    def encryptions(self):return sum(call[:2]==['systemd-creds','encrypt'] for call in self.fixture.calls)
    def test_wrong_original_address_is_rejected_before_encryption_or_persistent_key_publication(self):
        with self.assertRaises(ValueError):
            self.module.stage(self.state,self.expected,self.intent,self.profile,self.helpers,self.raw.hex(),
                derive=lambda value:self.public,identify=lambda point:'0x'+'ef'*20)
        self.assertEqual(self.encryptions(),0);self.assertFalse(self.state.path(self.module.STAGED_DIR).exists())
    def test_published_pair_retry_reuses_original_ciphertext_and_rebinds_new_intent(self):
        self.stage();cipher=self.state.path(self.module.STAGED).read_bytes();count=self.encryptions()
        self.intent='c'*32;self.state.prepare(self.expected,self.intent,self.profile,self.helpers)
        self.assertTrue(self.stage()['original_pending_reused'])
        self.assertEqual(self.state.path(self.module.STAGED).read_bytes(),cipher)
        self.assertEqual(self.encryptions(),count)
        self.assertEqual(self.state.read(self.module.STAGE_RECEIPT)['intent'],self.intent)
        with self.assertRaisesRegex(ValueError,'cannot be replaced'):
            self.stage(bytes([236])*32,lambda value:bytes([4])+bytes(reversed(range(64))))
        self.assertEqual(self.encryptions(),count)
    def test_interrupted_atomic_publication_recovers_the_exact_original_without_reencryption(self):
        import host
        publish=host.publish
        def interrupted(source,destination,**kwargs):
            publish(source,destination,**kwargs)
            if destination==self.state.path(self.module.STAGED_DIR):raise OSError('inert crash after durable publication')
        with patch.object(host,'publish',side_effect=interrupted):
            with self.assertRaises(OSError):self.stage()
        count=self.encryptions()
        self.assertTrue(self.stage()['original_pending_reused'])
        self.assertEqual(self.encryptions(),count)
        self.assertFalse(self.state.path(self.module.STAGED_DIR+'.pending').exists())
    def test_encryption_failure_publishes_nothing_and_cancelled_stage_cannot_reappear(self):
        self.fixture.fail=True
        with self.assertRaises(subprocess.CalledProcessError):self.stage()
        self.assertFalse(self.state.path(self.module.STAGED_DIR).exists())
        self.assertFalse(self.state.path(self.module.STAGED_DIR+'.pending').exists())
        self.fixture.fail=False;self.state.invalidate('stopped');count=self.encryptions()
        with self.assertRaises(ValueError):self.stage()
        self.assertEqual(self.encryptions(),count)
    def test_cipher_damage_refuses_before_overwrite_or_native_conversion(self):
        self.stage();self.state.path(self.module.STAGED).write_bytes(b'inert damaged encrypted original')
        count=self.encryptions()
        with self.assertRaises(ValueError):self.stage()
        with self.assertRaises(ValueError):self.module.material(self.state,self.expected,self.intent,self.profile,
            Path('inert-bor'),Path('inert-heimdall'),'fixture',converter=lambda *args:self.fail('must not convert'))
        self.assertEqual(self.encryptions(),count)

if __name__=='__main__':unittest.main()

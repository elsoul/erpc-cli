# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert known scalar and opaque encryption fixtures; no operational key or node."""
import os
import json
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parents[1]/'templates/node'))
import erpc_hl_common as common
import erpc_hl_state as lifecycle
import erpc_hl_validator as custody

# Standard secp256k1 generator, a public verification point (scalar one).
PUBLIC='04'+'79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'+'483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'


class Custody(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.root=Path(self.temporary.name).resolve()
        self.state_dir=self.root/'state';self.state_dir.mkdir();self.credentials=self.root/'credentials'
        self.raw=common.json_bytes({'key':'00'*31+'01'})
        self.contract={'owner':'a'*32,'network':'testnet','role':'validator','public_ip':'8.8.8.8',
            'validator':{'validator':'0x'+'ab'*20,'signer':'0x7e5f4552091a69125d5dfcb7b8c2659029395bdf','signer_public_key':PUBLIC,'max_hot_usdc':'0.01'}}
        self.state=lifecycle.State(self.state_dir)
        self.state.put('owner.json',{'contract':self.contract})
        self.state.put('accounts.json',{custody.setup.NATIVE:{'uid':os.getuid(),'gid':os.getgid()}})
        (self.state_dir/'retained-native-history').write_bytes(b'preserved')
        self.patches=[];self.stops=0;self.encryptions=0;self.calls=[]
        def install(obj,name,value):
            item=patch.object(obj,name,value);item.start();self.patches.append(item)
        def directories(path,create=False,mode=0o700):
            if create:path.mkdir(parents=True,exist_ok=True,mode=mode)
            self.assertTrue(path.is_dir() and not path.is_symlink())
            self.assertFalse(path.stat().st_mode&0o022)
        install(custody,'ROOT',self.state_dir);install(custody,'CREDENTIALS',self.credentials)
        install(custody,'ACTIVE',self.credentials/custody.NAME)
        install(custody,'DECRYPTED',self.root/'runtime.json');install(custody,'ROOT_UID',os.getuid())
        install(custody,'owned_directory',directories)
        install(custody,'read',lambda path,limit=1048576:common.read(path,limit,os.getuid()))
        install(lifecycle,'read',lambda path:common.read(path,owner=os.getuid()))
        install(custody.setup,'accounts',lambda _:None)
        install(custody,'execute',self.execute)
        self.filesystem_uuid='00000000-0000-0000-0000-000000000001'
        self.filesystem_type='ext4';self.filesystem_root='/';self.filesystem_options='rw,relatime'
        self.mounts=self.root/'mountinfo';self.mounts.write_text('1 0 1:1 / / rw - ext4 /dev/inert rw\n')
        install(custody.setup,'ROOT',self.state_dir);install(custody.setup,'MOUNTINFO',self.mounts)

    def tearDown(self):
        for item in reversed(self.patches):item.stop()
        self.temporary.cleanup()

    def stop(self): self.stops+=1

    def execute(self,argv,**kwargs):
        self.calls.append(argv)
        self.assertNotIn('00'*31+'01',' '.join(argv))
        if argv[0]=='/usr/bin/findmnt':
            device=self.state_dir.lstat().st_dev
            return SimpleNamespace(stdout=json.dumps({'filesystems':[{'uuid':self.filesystem_uuid,
                'fstype':self.filesystem_type,'fsroot':self.filesystem_root,'options':self.filesystem_options,
                'maj:min':str(os.major(device))+':'+str(os.minor(device))}]}).encode())
        if argv[0].endswith('openssl'):
            return SimpleNamespace(stdout=custody.PUBLIC_DER_PREFIX+bytes.fromhex(PUBLIC))
        if argv[:2]==['/usr/bin/systemd-creds','decrypt']:
            self.assertEqual(argv[2],'--name='+custody.NAME)
            return SimpleNamespace(stdout=self.raw)
        self.assertEqual(argv[:3],['/usr/bin/systemd-creds','encrypt','--name='+custody.NAME])
        self.assertEqual(kwargs['input_data'],self.raw)
        self.encryptions+=1
        Path(argv[-1]).write_bytes(('inert opaque ciphertext generation '+str(self.encryptions)).encode())
        return SimpleNamespace(stdout=b'')

    def import_key(self,restore=False,raw=None,unhosted=True):
        return custody.import_original(self.contract,self.raw if raw is None else raw,
            restore=restore,unhosted=unhosted,stop=self.stop)

    def test_actual_public_derivation_uses_only_stdin_and_original_native_object(self):
        with patch.object(custody,'execute',common.execute):
            self.assertEqual(custody.material(self.raw,self.contract),common.digest(self.raw))
            with self.assertRaises(ValueError):custody.material(common.json_bytes({'key':'00'*32}),self.contract)

    def test_first_original_import_retry_and_same_bytes_restore_preserve_old_ciphertext(self):
        self.import_key();original=custody.ACTIVE.read_bytes()
        self.assertEqual(self.encryptions,1)
        self.import_key();self.assertEqual(self.encryptions,1)
        self.import_key(restore=True);self.assertEqual(self.encryptions,2)
        old=self.credentials/(custody.NAME+'.previous.'+common.digest(original))
        self.assertEqual(old.read_bytes(),original)
        self.assertEqual(old.stat().st_nlink,1);self.assertEqual(custody.ACTIVE.stat().st_nlink,1)
        self.assertNotEqual(old.stat().st_ino,custody.ACTIVE.stat().st_ino)
        self.assertEqual(custody.identity(self.contract)['plaintext_sha256'],common.digest(self.raw))
        self.assertEqual((self.state_dir/'retained-native-history').read_bytes(),b'preserved')

    def test_account_drift_and_wrong_scope_refuse_before_key_tools_or_shutdown(self):
        with patch.object(custody.setup,'accounts',side_effect=ValueError('inert account drift')):
            with self.assertRaises(ValueError):self.import_key()
        self.assertEqual(self.calls,[]);self.assertEqual(self.stops,0)
        self.contract=dict(self.contract,network='mainnet')
        with self.assertRaises(ValueError):self.import_key()
        self.assertEqual(self.calls,[]);self.assertEqual(self.stops,0)

    def test_changed_original_bytes_or_unknown_ciphertext_cannot_be_adopted(self):
        with self.assertRaises(ValueError):self.import_key(unhosted=False)
        self.assertEqual(self.encryptions,0)
        self.import_key();count=self.encryptions
        with self.assertRaises(ValueError):self.import_key(restore=True,raw=b' '+self.raw)
        self.assertEqual(self.encryptions,count)
        self.state_dir.joinpath('validator-identity.json').unlink()
        with self.assertRaisesRegex(ValueError,'unowned'):self.import_key()
        self.assertEqual(self.encryptions,count)

    def test_failed_encrypted_readback_never_publishes_original_receipt(self):
        execute=self.execute
        def corrupt(argv,**kwargs):
            if argv[:2]==['/usr/bin/systemd-creds','decrypt']:
                return SimpleNamespace(stdout=self.raw+b' ')
            return execute(argv,**kwargs)
        with patch.object(custody,'execute',corrupt),self.assertRaisesRegex(ValueError,'read-back'):
            self.import_key()
        self.assertFalse((self.state_dir/'validator-identity.json').exists())
        self.assertFalse(custody.ACTIVE.exists())
        self.assertEqual(list(self.credentials.iterdir()),[])
        self.assertEqual(self.stops,1)

    def test_fresh_host_refuses_orphan_cipher_staging_without_adopting_it(self):
        self.credentials.mkdir()
        custody.fresh_namespace()
        for name in (custody.NAME,custody.NAME+'.previous.inert','.erpc-hl-consensus-orphan'):
            path=self.credentials/name;path.write_bytes(b'inert opaque retained bytes')
            with self.assertRaisesRegex(ValueError,'unowned'):custody.fresh_namespace()
            self.assertEqual(path.read_bytes(),b'inert opaque retained bytes')
            path.unlink()

    def test_failed_cancellation_still_drains_and_never_replaces_encrypted_material(self):
        self.import_key();before=custody.ACTIVE.read_bytes();calls=self.stops
        with patch.object(lifecycle.State,'marker',side_effect=OSError('inert marker write failure')):
            with self.assertRaisesRegex(ValueError,'not persisted'):self.import_key(restore=True)
        self.assertEqual(self.stops,calls+1);self.assertEqual(custody.ACTIVE.read_bytes(),before)
        self.assertEqual(self.encryptions,1)

    def test_interrupted_cipher_publication_retains_referenced_candidate_and_recovers_once(self):
        original=os.replace
        def fail(source,destination):
            if Path(destination)==custody.ACTIVE:raise OSError('inert active publication failure')
            original(source,destination)
        with patch.object(os,'replace',fail),self.assertRaises(OSError):self.import_key()
        self.assertFalse(custody.ACTIVE.exists())
        expected=custody.receipt(self.contract)
        self.assertTrue((self.credentials/expected['pending_file']).exists())
        self.import_key();self.assertEqual(self.encryptions,1)
        custody.identity(self.contract)

    def test_private_links_and_changed_decrypted_material_fail_before_runtime(self):
        self.import_key();custody.DECRYPTED.write_bytes(self.raw);custody.DECRYPTED.chmod(0o400)
        self.assertEqual(custody.verify_runtime(self.contract)['custody'],'original')
        custody.DECRYPTED.chmod(0o440)
        self.assertEqual(custody.verify_runtime(self.contract)['custody'],'original')
        custody.DECRYPTED.chmod(0o644)
        with self.assertRaises(ValueError):custody.verify_runtime(self.contract)
        custody.DECRYPTED.chmod(0o600)
        custody.DECRYPTED.write_bytes(self.raw+b' ');custody.DECRYPTED.chmod(0o400)
        with self.assertRaises(ValueError):custody.verify_runtime(self.contract)
        os.link(custody.ACTIVE,self.credentials/'inert-alias')
        with self.assertRaisesRegex(ValueError,'shared'):custody.identity(self.contract)
        (self.credentials/'inert-alias').unlink();custody.ACTIVE.chmod(0o644)
        with self.assertRaises(ValueError):custody.identity(self.contract)

    def test_every_first_import_fsync_failure_preserves_original_retry_and_native_history(self):
        real=os.fsync;count=[0]
        def counted(fd):count[0]+=1;return real(fd)
        with patch.object(os,'fsync',side_effect=counted):self.import_key()
        self.assertGreater(count[0],8)
        for failure in range(1,count[0]+1):
            with self.subTest(fsync=failure):
                fixture=Custody('test_first_original_import_retry_and_same_bytes_restore_preserve_old_ciphertext')
                fixture.setUp();seen=[0]
                try:
                    def interrupted(fd):
                        seen[0]+=1
                        if seen[0]==failure:raise OSError('inert persistence fault')
                        return real(fd)
                    with patch.object(os,'fsync',side_effect=interrupted),self.assertRaises((OSError,ValueError)):
                        fixture.import_key()
                    self.assertGreaterEqual(fixture.stops,1)
                    fixture.import_key()
                    self.assertEqual(custody.identity(fixture.contract)['plaintext_sha256'],common.digest(fixture.raw))
                    self.assertEqual((fixture.state_dir/'retained-native-history').read_bytes(),b'preserved')
                    for path in fixture.credentials.iterdir():
                        self.assertEqual(path.stat().st_nlink,1)
                        self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
                finally:fixture.tearDown()

    def test_native_private_path_cannot_adopt_unknown_key_or_reset_original_history(self):
        self.import_key()
        home=self.state_dir/'home';data=home/'hl/data';data.mkdir(parents=True)
        self.state.put('accounts.json',{custody.setup.NATIVE:{'uid':1000,'gid':1000}})
        ownership={};actual=os.fstat
        def metadata(fd):
            info=actual(fd)
            if info.st_ino in ownership:
                fields=list(info);fields[4],fields[5]=ownership[info.st_ino];return os.stat_result(fields)
            return info
        def chown(fd,uid,gid):ownership[actual(fd).st_ino]=(uid,gid)
        with patch.object(custody.setup,'HOME',home), \
             patch.object(custody.setup,'storage_descriptor',side_effect=lambda _: (os.open(data,os.O_RDONLY),True)), \
             patch.object(custody.processes,'quiescent') as idle,patch.object(os,'fstat',metadata),patch.object(os,'fchown',chown):
            path=Path(custody.native_path(self.contract,create=True))
            self.assertEqual(path.read_bytes(),custody.PLACEHOLDER)
            self.assertEqual(custody.native_path(self.contract),str(path))
            idle.assert_called_once_with([1000])
            path.write_bytes(b'inert unknown native configuration')
            with self.assertRaises(ValueError):custody.native_path(self.contract,create=True)
            self.assertEqual(path.read_bytes(),b'inert unknown native configuration')
            path.write_bytes(custody.PLACEHOLDER)
            previous=path.parent.with_name('retained-private-history');path.parent.rename(previous)
            path.parent.mkdir(mode=0o700);ownership[path.parent.stat().st_ino]=(1000,1000)
            with self.assertRaisesRegex(ValueError,'history reset'):custody.native_path(self.contract,create=True)
            self.assertEqual((previous/'node_config.json').read_bytes(),custody.PLACEHOLDER)


if __name__=='__main__':unittest.main()

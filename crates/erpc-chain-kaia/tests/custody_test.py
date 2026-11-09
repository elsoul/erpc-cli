# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Deterministic public fixtures; no operational keys or system credentials."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
SOURCE=Path(__file__).parents[1]/'templates/node'
def load(name):
    spec=importlib.util.spec_from_file_location('kaia_'+name,SOURCE/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
c=load('control');k=load('custody')

class Custody(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);self.addCleanup(patch.stopall)
        self.root=Path(temporary.name);self.calls=[];self.saved=None;self.encryption_nonce=0
        patch.object(c,'ROOT',self.root/'owner').start();c.ROOT.mkdir(mode=0o700)
        patch.object(c,'TRUST_ANCHOR',self.root).start();patch.object(c,'ROOT_UID',os.getuid()).start()
        machine=self.root/'machine-id';machine.write_text('a'*32);patch.object(k,'MACHINE_ID',machine).start()
        patch.object(c,'save',side_effect=self.save).start();patch.object(c,'run',side_effect=self.command).start()
        patch.object(k.secrets,'token_bytes',return_value=hashlib.sha256(b'public custody fixture').digest()).start()
        self.state={'owner':'fixture','network':'kairos','role':'validator','node_kind':'cn','phase':'prepared','startup_revoked':True,'service_uid':os.getuid()}
        self.public={'address':'0x'+'a'*40,'peer_key':'a'*128,'bls_key':'a'*96,'bls_pop':'a'*192}
    def save(self,state):
        self.saved=copy.deepcopy(state)
        path=c.ROOT/'owner.json';path.write_text(json.dumps(state));path.chmod(0o600)
    def command(self,argv,**kwargs):
        self.calls.append(argv)
        if argv[1]=='encrypt':
            self.encryption_nonce+=1
            target=Path(argv[-1]);target.write_bytes(b'fixture encrypted:'+str(self.encryption_nonce).encode()+b':'+kwargs['input']);target.chmod(0o600);return b''
        self.assertEqual(argv[1],'decrypt');parts=Path(argv[-2]).read_bytes().split(b':',2)
        c.require(len(parts)==3,'inert decryption failure');return parts[2]
    def ready(self):
        raw=k.create(c,self.state)
        k.acknowledge(c,self.state,{'backup_digest':hashlib.sha256(raw).hexdigest(),'public':self.public})
        return raw
    def test_original_cipher_and_plaintext_survive_repeated_creation(self):
        raw=self.ready();path=c.ROOT/'identity/corecell.cred';before=path.read_bytes()
        with patch.object(k.secrets,'token_bytes',side_effect=AssertionError('regenerated')):
            self.assertEqual(k.create(c,self.state),raw);self.assertEqual(k.read(c,self.state)[0],raw)
        self.assertEqual(path.read_bytes(),before)
    def test_interrupted_receipt_publication_reuses_cipher_without_entropy(self):
        with patch.object(k.os,'replace',side_effect=OSError('injected rename')):
            with self.assertRaises(OSError):k.create(c,self.state)
        state=copy.deepcopy(self.saved);pending=c.ROOT/'identity/corecell.pending';before=pending.read_bytes()
        with patch.object(k.secrets,'token_bytes',side_effect=AssertionError('regenerated')):
            k.create(c,state)
        self.assertEqual((c.ROOT/'identity/corecell.cred').read_bytes(),before)
        self.assertFalse(pending.exists())
    def test_missing_or_changed_established_cipher_never_regenerates(self):
        self.ready();path=c.ROOT/'identity/corecell.cred';path.unlink()
        with patch.object(k.secrets,'token_bytes',side_effect=AssertionError('regenerated')):
            with self.assertRaises(c.Refused):k.create(c,self.state)
        path.write_bytes(b'foreign');path.chmod(0o600)
        with self.assertRaises(c.Refused):k.read(c,self.state)
    def test_unowned_directory_and_partial_staging_are_not_adopted(self):
        directory=c.ROOT/'identity';directory.mkdir(mode=0o700)
        with self.assertRaises(c.Refused):k.create(c,self.state)
        self.assertFalse(self.state.get('custody_creating'))
        directory.rmdir();self.state['custody_creating']=True;directory.mkdir(mode=0o700)
        (directory/'corecell.pending').write_bytes(b'incomplete');(directory/'corecell.pending').chmod(0o600)
        with self.assertRaises(c.Refused):k.create(c,self.state)
        self.assertNotIn('custody_digest',self.state)
    def test_backup_acknowledgment_is_exact_and_public_identity_immutable(self):
        raw=k.create(c,self.state)
        with self.assertRaises(c.Refused):k.acknowledge(c,self.state,{'backup_digest':'b'*64,'public':self.public})
        self.assertFalse(self.state.get('backup_confirmed'))
        self.ready();changed=dict(self.public,address='0x'+'b'*40)
        with self.assertRaises(c.Refused):k.acknowledge(c,self.state,{'backup_digest':hashlib.sha256(raw).hexdigest(),'public':changed})
    def test_same_host_stopped_restore_preserves_original_and_resumes_after_rename_failure(self):
        raw=self.ready();self.state['phase']='installed';self.save(self.state);old_cipher=self.state['custody_cipher'];path=c.ROOT/'identity/corecell.cred';path.unlink()
        with patch.object(k.os,'replace',side_effect=OSError('injected rename')):
            with self.assertRaises(OSError):k.restore(c,self.state,raw)
        state=copy.deepcopy(self.saved)
        with patch.object(k.secrets,'token_bytes',side_effect=AssertionError('regenerated')):
            self.assertTrue(k.restore(c,state,raw)['restored'])
        self.assertEqual(k.read(c,state)[0],raw);self.assertEqual(state['custody_public'],self.public)
        self.assertNotEqual(state['custody_cipher'],old_cipher)
        self.assertFalse(k.restore(c,state,raw)['restored'])
    def test_recovery_refuses_foreign_binding_scope_unbacked_and_active_owner(self):
        raw=self.ready();self.state['phase']='installed';self.save(self.state);path=c.ROOT/'identity/corecell.cred';before=path.read_bytes()
        for key,value in (('owner','foreign'),('network','mainnet'),('node_kind','pn'),('binding','b'*64)):
            item=json.loads(raw);item[key]=value
            with self.assertRaises(c.Refused):k.restore(c,self.state,json.dumps(item).encode())
        for change in ({'backup_confirmed':False},{'startup_revoked':False}):
            with self.assertRaises(c.Refused):k.restore(c,dict(self.state,**change),raw)
        self.assertEqual(path.read_bytes(),before)
    def test_interrupted_or_retired_owner_can_restore_without_reactivating_or_losing_target(self):
        raw=self.ready();path=c.ROOT/'identity/corecell.cred'
        for phase in ('installing','retired'):
            path.unlink();self.state.update(phase=phase,startup_revoked=True,target={'fixture':'retained'});self.save(self.state)
            k.restore(c,self.state,raw)
            self.assertEqual(self.state['phase'],phase);self.assertTrue(self.state['startup_revoked'])
            self.assertEqual(self.state['target'],{'fixture':'retained'})
            self.assertEqual(k.read(c,self.state)[0],raw)

    def test_private_cipher_rejects_links_modes_and_missing_host_binding(self):
        self.ready();path=c.ROOT/'identity/corecell.cred';alias=path.with_name('alias');os.link(path,alias)
        with self.assertRaises(c.Refused):k.read(c,self.state)
        alias.unlink();path.chmod(0o640)
        with self.assertRaises(c.Refused):k.read(c,self.state)
        path.chmod(0o600);k.MACHINE_ID.write_text('b'*32)
        with self.assertRaises(c.Refused):k.read(c,self.state)
    def test_runtime_keys_require_backup_and_preserve_exact_original_readonly_bytes(self):
        self.ready();directory=self.root/'runtime';gid=os.getgid()
        with self.assertRaises(c.Refused):k.materialize(c,dict(self.state,backup_confirmed=False),directory,gid)
        self.assertFalse(directory.exists())
        previous=os.umask(0o077)
        try:k.materialize(c,self.state,directory,gid)
        finally:os.umask(previous)
        self.assertEqual(directory.stat().st_mode&0o777,0o750)
        for name in ('nodekey','bls-nodekey'):
            self.assertEqual((directory/name).stat().st_mode&0o777,0o400)
            self.assertEqual((directory/name).stat().st_uid,self.state['service_uid'])
        k.materialize(c,self.state,directory,gid)
        (directory/'nodekey').chmod(0o640)
        with self.assertRaises(c.Refused):k.materialize(c,self.state,directory,gid)
    def test_runtime_foreign_artifacts_and_writable_ancestors_are_refused(self):
        self.ready();directory=self.root/'runtime';directory.mkdir();foreign=directory/'foreign';foreign.write_text('retained')
        with self.assertRaises(c.Refused):k.materialize(c,self.state,directory,os.getgid())
        self.assertEqual(foreign.read_text(),'retained');foreign.unlink();directory.chmod(0o777)
        with self.assertRaises(c.Refused):k.materialize(c,self.state,directory,os.getgid())

if __name__=='__main__':unittest.main()

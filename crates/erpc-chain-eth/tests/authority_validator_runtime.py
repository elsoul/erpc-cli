# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real volatile-file publication with inert original numeric ownership projection."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import authority_accounts as fixtures
import eth_validator_runtime as runtime


class Runtime(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.Accounts();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.state=self.f.state;self.c=self.f.c;self.plan=fixtures.accounts.provision(self.state,'validator');self.owners={}
        self.f.install(runtime.custody,'machine',lambda:'b'*64);self.f.install(runtime,'boot',lambda:'inert-boot')
        self.f.install(runtime.native,'RUN',self.f.root/'run');self.f.install(runtime.native,'volatile',lambda _:1)
        actual=os.fstat
        def metadata(fd):
            value=list(actual(fd));value[4],value[5]=self.owners.get((value[2],value[1]),(0,0));return os.stat_result(value)
        def owner(fd,uid,gid):
            info=actual(fd);fixtures.hold(self,fd);self.owners[(info.st_dev,info.st_ino)]=(uid,gid)
        self.f.install(os,'fstat',metadata);self.f.install(os,'fchown',owner)
        self.stops=[];runtime.prepare(self.state,self.c,lambda:self.stops.append('original quiescence'))

    def grant(self,value=b'inert original password'):
        runtime.grant(self.state,self.c,'validator/password',value,lambda name:self.stops.append(name))

    def test_original_grant_has_private_numeric_owner_and_repeat_does_not_replace_inode(self):
        self.grant();path=runtime.native.RUN/'validator/password';before=path.stat().st_ino
        self.assertEqual(path.read_bytes(),b'inert original password');self.assertEqual(path.stat().st_mode&0o777,0o400)
        self.assertEqual(self.owners[(path.stat().st_dev,path.stat().st_ino)],tuple(self.plan['users']['ev-validator'].values()))
        self.grant();self.assertEqual(path.stat().st_ino,before)
        self.assertEqual(self.stops,['original quiescence','validator/password'])

    def test_changed_credentials_require_stopped_cutover_and_quiescence_not_just_receipt(self):
        self.grant();path=runtime.native.RUN/'validator/password'
        with self.assertRaises(FileNotFoundError):self.grant(b'inert replacement')
        self.state.authorize(self.c,'c'*32,{},'deploy');self.state.begin(self.c,'c'*32,lambda:None)
        def refuse(_):raise ValueError('inert original writer still present')
        with self.assertRaises(ValueError):runtime.grant(self.state,self.c,'validator/password',b'inert replacement',refuse)
        self.assertEqual(path.read_bytes(),b'inert original password')
        self.grant(b'inert replacement');self.assertEqual(path.read_bytes(),b'inert replacement')

    def test_pending_rotated_credential_after_rename_can_finish_without_overwriting_the_original_again(self):
        self.grant();self.state.authorize(self.c,'c'*32,{},'deploy');self.state.begin(self.c,'c'*32,lambda:None)
        original=self.state.put
        def fail(name,value):
            if name=='runtime-file-validator-password.json':raise OSError('inert final receipt failure')
            original(name,value)
        with patch.object(self.state,'put',side_effect=fail):
            with self.assertRaises(OSError):self.grant(b'inert replacement')
        path=runtime.native.RUN/'validator/password';inode=path.stat().st_ino
        self.grant(b'inert replacement');self.assertEqual(path.stat().st_ino,inode)
        self.assertEqual(path.read_bytes(),b'inert replacement')

    def test_alias_or_unknown_current_plaintext_is_not_adopted_or_repaired(self):
        path=runtime.native.RUN/'validator/password';outside=self.f.root/'outside';outside.write_bytes(b'inert unrelated bytes')
        path.symlink_to(outside)
        with self.assertRaises(OSError):self.grant()
        self.assertEqual(outside.read_bytes(),b'inert unrelated bytes');path.unlink()
        path.write_bytes(b'inert unowned content');path.chmod(0o400)
        fixtures.hold(self,path);self.owners[(path.stat().st_dev,path.stat().st_ino)]=tuple(self.plan['users']['ev-validator'].values())
        with self.assertRaisesRegex(ValueError,'original authority'):self.grant()
        self.assertEqual(path.read_bytes(),b'inert unowned content')

    def key(self,path):info=path.stat();return (info.st_dev,info.st_ino)
    def receipts(self):return {path.name:path.read_bytes() for path in self.state.directory.iterdir()}

    def test_password_of_another_owner_or_group_is_neither_reused_nor_replaced(self):
        self.grant();path=runtime.native.RUN/'validator/password';key=self.key(path);owner=self.owners[key]
        raw=path.read_bytes();receipts=self.receipts();stops=list(self.stops)
        refused='managed file is indirect, shared, foreign or has unsafe permissions';group='original credential grant group or size differs'
        for value,message in [((77,owner[1]),refused),((0,owner[1]),refused),((owner[0],77),group)]:
            with self.subTest(owner=value):
                self.owners[key]=value
                try:
                    with self.assertRaisesRegex(ValueError,message):self.grant()
                finally:self.owners[key]=owner
                self.assertEqual((self.key(path),path.read_bytes(),self.receipts(),self.stops),(key,raw,receipts,stops))
        self.grant();self.assertEqual(self.key(path),key);self.assertEqual(self.stops,stops)

    def test_runtime_directory_with_another_owner_or_inode_refuses_every_grant(self):
        run=runtime.native.RUN;outside=self.f.root/'outside';trust=run/'trust'
        validator=self.key(run/'validator');engine=self.key(run/'engine');saved=dict(self.owners);before=self.receipts()
        def owned(key,value):return lambda:self.owners.__setitem__(key,value)
        def replace():trust.rename(outside);trust.mkdir();trust.chmod(0o755)
        def restore():trust.rmdir();outside.rename(trust)
        for name,change,undo in [('root directory of another account',owned(validator,(77,0)),None),
                                 ('engine directory of another group',owned(engine,(self.owners[engine][0],77)),None),
                                 ('replaced trust directory',replace,restore)]:
            with self.subTest(name):
                change()
                try:
                    with self.assertRaisesRegex(ValueError,'original runtime directory ownership or identity changed'):self.grant()
                finally:
                    if undo:undo()
                    self.owners.clear();self.owners.update(saved)
                self.assertFalse((run/'validator/password').exists());self.assertEqual(self.stops,['original quiescence'])
                self.assertEqual(self.receipts(),before)
        self.grant();self.assertEqual(self.stops,['original quiescence','validator/password'])

    def test_unfinished_runtime_never_adopts_a_directory_of_another_identity(self):
        import shutil
        shutil.rmtree(runtime.native.RUN);actual=self.state.put
        def interrupted(name,value):
            if name=='runtime.json':raise OSError('inert interruption before the runtime receipt')
            return actual(name,value)
        with patch.object(runtime,'boot',return_value='next-boot'):
            with patch.object(self.state,'put',side_effect=interrupted):
                with self.assertRaises(OSError):runtime.prepare(self.state,self.c,lambda:None)
            run=runtime.native.RUN;receipt=self.state.path('runtime.json').read_bytes()
            trust=self.key(run/'trust');engine=self.key(run/'engine');saved=dict(self.owners)
            validator=tuple(self.plan['users']['ev-validator'].values())
            cases=[('foreign owner',trust,(77,0)),('foreign group',trust,(0,77)),('another service account',engine,validator)]
            for name,key,value in cases:
                with self.subTest(name):
                    self.owners[key]=value
                    try:
                        with self.assertRaisesRegex(ValueError,'unfinished runtime contains an unknown identity or payload'):
                            runtime.prepare(self.state,self.c,lambda:None)
                        self.assertEqual(self.owners[key],value)
                    finally:self.owners.clear();self.owners.update(saved)
                    self.assertEqual(self.state.path('runtime.json').read_bytes(),receipt)
            self.assertEqual(runtime.prepare(self.state,self.c,lambda:None)['boot'],'next-boot')

    def test_nss_drift_precedes_file_creation_and_boot_change_requires_new_empty_runtime(self):
        self.f.users['ev-validator'].pw_uid=777
        with self.assertRaises(ValueError):self.grant()
        self.assertFalse((runtime.native.RUN/'validator/password').exists())
        self.f.users['ev-validator'].pw_uid=self.plan['users']['ev-validator']['uid']
        with patch.object(runtime,'boot',return_value='different-boot'):
            with self.assertRaises(ValueError):runtime.prepare(self.state,self.c,lambda:None)


if __name__=='__main__':unittest.main()

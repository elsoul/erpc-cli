# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Private engine material publication with a fixed inert public byte fixture."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import authority_runtime as fixtures
import control
ORIGINAL_CHECK=control.jwt


class EngineMaterial(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.Runtime();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        f=self.fixture;self.state=f.state;self.c=f.c;self.path=f.root/'config'/'jwt.hex';self.generated=0
        self.ownership={};fstat=os.fstat;lstat=Path.lstat
        def owner(fd,uid,gid):
            value=fstat(fd);fixtures.fixtures.hold(self,fd);self.ownership[(value.st_dev,value.st_ino)]=(uid,gid)
        def metadata(path):
            value=list(lstat(path));key=(value[2],value[1])
            if key in self.ownership:value[4],value[5]=self.ownership[key]
            return os.stat_result(value)
        f.install(os,'fchown',owner);f.install(Path,'lstat',metadata);f.install(control,'jwt',ORIGINAL_CHECK)
        def native(args,**kwargs):
            if args==['/usr/bin/openssl','rand','-hex','32']:
                self.generated+=1;return b'0'*64+b'\n'
            return f.native(args,**kwargs)
        f.install(control,'run',native)
        f.reserve_target();f.request('begin',intent=f.intent)

    def execute(self):return self.fixture.request('engine-init',intent=self.fixture.intent)

    def test_same_original_pending_material_survives_failure_before_its_receipt(self):
        original=self.state.put
        def failed(name,value):
            if name=='engine-jwt.json':raise OSError('inert receipt failure')
            return original(name,value)
        with patch.object(self.state,'put',side_effect=failed):
            for _ in range(2):
                with self.assertRaises(OSError):self.execute()
        self.assertEqual(self.generated,1);pending=self.path.with_name('jwt.pending').read_bytes()
        self.execute();self.assertEqual(self.path.read_bytes(),pending);self.assertEqual(self.generated,1)
        self.execute();self.assertEqual(self.generated,1)

    def test_visible_original_intent_must_be_durable_before_any_material_generation(self):
        actual=os.fsync
        def failed(fd):
            if self.state.exists('engine-jwt-intent.json'):raise OSError('inert persistent intent persistence')
            actual(fd)
        with patch.object(os,'fsync',side_effect=failed):
            for _ in range(2):
                with self.assertRaises(OSError):self.execute()
                self.assertEqual(self.generated,0)
        self.execute();self.assertEqual(self.generated,1)

    def test_original_receipt_is_reused_after_rename_interruption_and_unknown_links_refuse(self):
        actual=os.replace
        def failed(source,destination,*args,**kwargs):
            if isinstance(destination,Path) and destination==self.path:raise OSError('inert final JWT publication interruption')
            return actual(source,destination,*args,**kwargs)
        with patch.object(os,'replace',side_effect=failed):
            with self.assertRaises(OSError):self.execute()
        self.assertTrue(self.state.exists('engine-jwt.json'));self.assertFalse(self.path.exists())
        outside=self.fixture.root/'outside';outside.write_bytes(b'original unrelated bytes')
        self.path.symlink_to(outside)
        with self.assertRaises((ValueError,OSError)):self.execute()
        self.assertEqual(outside.read_bytes(),b'original unrelated bytes')
        self.path.unlink();self.execute();self.assertEqual(self.generated,1)

    def test_staged_material_of_another_group_is_never_published(self):
        original=self.state.put
        def failed(name,value):
            if name=='engine-jwt.json':raise OSError('inert receipt failure')
            return original(name,value)
        with patch.object(self.state,'put',side_effect=failed):
            with self.assertRaises(OSError):self.execute()
        pending=self.path.with_name('jwt.pending');info=pending.stat();key=(info.st_dev,info.st_ino)
        owner=self.ownership[key];raw=pending.read_bytes()
        for value in [(0,0),(0,77)]:
            with self.subTest(owner=value):
                self.ownership[key]=value
                try:
                    with self.assertRaisesRegex(ValueError,'engine JWT staging group changed'):self.execute()
                finally:self.ownership[key]=owner
                self.assertFalse(self.state.exists('engine-jwt.json'));self.assertFalse(self.path.exists())
                self.assertEqual(pending.read_bytes(),raw);self.assertEqual(self.generated,1)
        self.execute();self.assertEqual(self.path.read_bytes(),raw);self.assertEqual(self.generated,1)

    def test_published_material_must_keep_the_original_group_whatever_its_receipt_names(self):
        self.execute();info=self.path.stat();key=(info.st_dev,info.st_ino);owner=self.ownership[key]
        record=self.state.get('engine-jwt.json');plan=self.fixture.plan
        # The second case also names the other group in the receipt, so only
        # the original account plan can still refuse it.
        for name,receipt in [('changed group',record),('receipt naming the changed group',dict(record,gid=77))]:
            with self.subTest(name):
                self.ownership[key]=(0,77);self.state.put('engine-jwt.json',receipt)
                try:
                    with self.assertRaisesRegex(ValueError,'original private engine JWT differs'):control.jwt(self.state,self.c,plan)
                    self.assertFalse(self.fixture.request('public-status')['jwt'])
                finally:self.ownership[key]=owner;self.state.put('engine-jwt.json',record)
        control.jwt(self.state,self.c,plan);self.assertTrue(self.fixture.request('public-status')['jwt'])

    def test_old_continuation_after_stop_cannot_generate_private_material(self):
        self.state.stop(self.c,lambda:None)
        with self.assertRaises(ValueError):self.execute()
        self.assertEqual(self.generated,0);self.assertFalse(self.path.exists())


if __name__=='__main__':unittest.main()

# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual directory/receipt ordering; inert original NSS and mount observations."""
import importlib.util
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))


@unittest.skipUnless(os.name=='posix','broker host storage uses POSIX directory identity')
class Storage(unittest.TestCase):
    def setUp(self):
        import broker_storage,host
        self.storage,self.host=broker_storage,host
        spec=importlib.util.spec_from_file_location('polygon_broker_storage_fixture',ROOT/'tests/control.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.fixture=module.Lifecycle();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.state=self.fixture.state;self.profile=self.fixture.profile
        self.expected=dict(self.fixture.contract,role='validator',signer='0x'+'1'*40,stake_owner='0x'+'2'*40)
        self.profile['validator']={'phase':'observing','signer':self.expected['signer'],
            'sentries':[{'address':'8.8.8.8','bor_node_id':'a'*128,'heimdall_node_id':'b'*40}]}
        self.state.write('/etc/polygon/contract.json',dict(self.expected,runtime_protocol=3))
        volume=self.state.read('/etc/polygon/storage.json');volume['contract']=self.expected
        self.state.write('/etc/polygon/storage.json',volume)
        # Filesystem publication uses only this test process's own IDs; actual
        # distinct UID/NSS reservation/drift is exercised in accounts_test.py.
        self.account={'uid':os.getuid(),'gid':os.getgid()}
        self.state.accounts=SimpleNamespace(verify=lambda expected:{'broker':self.account})
        self.intent='c'*32;self.helpers=self.fixture.control.helpers
        for name in ('installed','intent'):
            self.state.path('/etc/polygon/'+name+'.json').unlink(missing_ok=True)
        self.state.prepare(self.expected,self.intent,self.profile,self.helpers)
        entry=patch.object(os,'fchown',side_effect=self.chown);entry.start();self.addCleanup(entry.stop)
        self.handoffs=[]

    def chown(self,fd,uid,gid):
        record=self.state.read(self.storage.RECEIPT)
        self.assertEqual(record['state'],'reserved');self.assertEqual(record['account'],{'uid':uid,'gid':gid})
        self.assertEqual(record['inode'],os.fstat(fd).st_ino)
        self.handoffs.append((uid,gid))  # No actual ownership/account change.

    def reserve(self):return self.storage.reserve(self.state,self.expected,self.intent,self.profile,self.helpers)

    def test_original_directory_is_reserved_durably_before_numeric_handoff_and_reused(self):
        receipt=self.reserve();self.assertEqual(receipt['state'],'established');self.assertEqual(len(self.handoffs),1)
        (self.state.path('/var/lib/polygon/broker')/'inert-retained-database').write_text('retained')
        self.assertEqual(self.reserve(),receipt);self.assertEqual(len(self.handoffs),1)

    def test_unknown_nonempty_or_redirected_directory_is_not_adopted(self):
        data=self.state.path('/var/lib/polygon/broker');data.mkdir(mode=0o700);(data/'foreign').touch()
        with self.assertRaises(ValueError):self.reserve()
        self.assertFalse(self.state.path(self.storage.RECEIPT).exists());self.assertEqual(self.handoffs,[])
        (data/'foreign').unlink();data.rmdir();target=self.state.root/'other';target.mkdir();data.symlink_to(target)
        with self.assertRaises(ValueError):self.reserve()
        self.assertFalse(self.state.path(self.storage.RECEIPT).exists())

    def test_interrupted_receipt_publication_resumes_the_original_empty_inode_only(self):
        original=self.state.write
        def write(path,value,*args,**kwargs):
            if path==self.storage.RECEIPT and value.get('state')=='established':raise OSError('inert interrupted receipt publication')
            return original(path,value,*args,**kwargs)
        with patch.object(self.state,'write',side_effect=write):
            with self.assertRaises(OSError):self.reserve()
        reserved=self.state.read(self.storage.RECEIPT);self.assertEqual(reserved['state'],'reserved')
        self.assertEqual(self.reserve()['inode'],reserved['inode'])

    def test_replaced_directory_or_missing_original_receipt_with_custody_is_refused(self):
        receipt=self.reserve();data=self.state.path('/var/lib/polygon/broker');data.rename(data.with_name('retained-broker'))
        data.mkdir(mode=0o700)
        with self.assertRaises(ValueError):self.reserve()
        self.assertEqual(self.state.read(self.storage.RECEIPT),receipt)
        self.state.path(self.storage.RECEIPT).unlink();self.state.write('/etc/polygon/broker-custody.json',{'inert':'retained'})
        with self.assertRaises(ValueError):self.reserve()
        self.assertEqual(len(self.handoffs),1)


if __name__=='__main__':unittest.main()

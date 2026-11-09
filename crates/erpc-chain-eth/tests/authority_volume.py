# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real RPC guard/upgrade and filesystem-parser fixtures; no mounts or native clients."""
import json
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import authority_runtime as runtime
import eth_layout as layout
import control

REAL_VERIFY=layout.verify
REAL_PROBE=layout.probe
VOLUME={'uuid':'12345678-1234-1234-1234-123456789abc','type':'ext4','root':'/'}


class Volume(unittest.TestCase):
    def setUp(self):
        self.f=runtime.Runtime();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.f.state.remove('layout.json');self.root=self.f.root/'native'
        self.f.install(layout,'ROOTS',{'rpc':self.root})
        real=os.fstat;owners=self.owners={};self.devices={}
        def metadata(fd):
            info=real(fd);row=list(info);key=(info.st_dev,info.st_ino)
            if key in owners:row[4],row[5]=owners[key]
            if key in self.devices:row[2]=self.devices[key]
            return os.stat_result(row)
        def chown(fd,uid,gid):
            info=real(fd);runtime.fixtures.hold(self,fd);owners[(info.st_dev,info.st_ino)]=(uid,gid)
        self.f.install(os,'fstat',metadata);self.f.install(os,'fchown',chown)
        self.mounts=self.f.root/'mountinfo';self.mounts.write_text('20 1 8:1 / / rw - ext4 /dev/inert rw\n')
        self.f.install(layout,'MOUNTS',self.mounts)
        layout.prepare(self.f.state,self.f.c,self.f.plan)
        self.layout=self.f.state.get('layout.json')
        self.f.install_target();self.f.state.put('snapshot.json',{'contract':self.f.c})
        self.f.request('activate',intent=self.f.intent)
        self.f.install(layout,'verify',REAL_VERIFY)
        self.f.calls.clear();self.retained=self.root/'reth'/'native-data';self.retained.write_bytes(b'unchanged native data')

    def renumber(self):
        for path in [self.root,*[p for p in self.root.iterdir() if p.is_dir()]]:self.renumbered(path,100)

    def renumbered(self,path,offset):
        key=runtime.fixtures.held(self,path);self.devices[key]=key[0]+offset

    def test_actual_ready_manual_and_boot_guards_accept_only_device_renumbering(self):
        state=self.f.state;before={name:state.path(name).read_bytes() for name in ('layout.json','volume.json','source-reth.json','source-reth-pending.json','source-lighthouse.json')}
        control.ready(state,self.f.c);self.renumber();control.ready(state,self.f.c)
        with patch.object(control,'State',return_value=state):control.boot('guard','reth.service')
        self.f.request('stop');self.assertTrue(self.f.request('start')['started'])
        self.assertEqual(before,{name:state.path(name).read_bytes() for name in before})
        self.assertEqual(self.retained.read_bytes(),b'unchanged native data')

    def test_foreign_uuid_same_device_and_recreated_inode_are_not_original(self):
        with patch.object(layout,'probe',return_value=dict(VOLUME,uuid='22345678-1234-1234-1234-123456789abc')):
            with self.assertRaisesRegex(ValueError,'UUID/type'):control.ready(self.f.state,self.f.c)
        child=self.root/'lighthouse';child.rename(self.root/'retained-old-lighthouse');child.mkdir(mode=0o700)
        with self.assertRaises(ValueError):control.ready(self.f.state,self.f.c)
        self.assertFalse(any('start' in call for call in self.f.calls))

    def test_same_observation_child_device_and_nested_bind_mount_are_refused(self):
        self.renumbered(self.root/'reth',1)
        with self.assertRaises(ValueError):control.ready(self.f.state,self.f.c)
        self.devices.clear();self.f.request('stop');self.f.state.remove('volume.json')
        self.mounts.write_text(f'20 1 8:1 / / rw - ext4 /dev/inert rw\n21 20 8:1 / {self.root}/reth/db rw - ext4 /dev/inert rw\n')
        with self.assertRaises(ValueError):self.f.request('upgrade-volume',filesystem=VOLUME)
        self.assertFalse(self.f.state.exists('volume.json'))

    def test_legacy_upgrade_uses_independent_uuid_and_never_rewrites_opened_source_or_starts(self):
        state=self.f.state;state.remove('volume.json');self.renumber()
        before={name:state.path(name).read_bytes() for name in ('layout.json','source-reth.json','source-lighthouse.json','snapshot.json')}
        with self.assertRaisesRegex(ValueError,'independent-evidence'):control.ready(state,self.f.c)
        with self.assertRaisesRegex(ValueError,'evidence differs'):
            self.f.request('upgrade-volume',filesystem=dict(VOLUME,uuid='22345678-1234-1234-1234-123456789abc'))
        self.assertFalse(state.exists('volume.json'))
        for _ in range(2):self.assertTrue(self.f.request('upgrade-volume',filesystem=VOLUME)['upgraded'])
        self.assertFalse(any('start' in call or '--now' in call for call in self.f.calls))
        self.assertEqual(before,{name:state.path(name).read_bytes() for name in before})
        with self.assertRaises(ValueError):state.guard(self.f.c)
        self.assertEqual(self.retained.read_bytes(),b'unchanged native data')

    def test_upgrade_never_binds_a_complete_child_with_another_owner_or_inode(self):
        state=self.f.state;state.remove('volume.json');child=self.root/'lighthouse';key=runtime.fixtures.held(self,child)
        owner=self.owners[key];reth=self.owners[runtime.fixtures.held(self,self.root/'reth')];outside=self.f.root/'outside'
        def owned(value):return lambda:self.owners.__setitem__(key,value)
        def replace():child.rename(outside);child.mkdir(mode=0o700);self.owners[runtime.fixtures.held(self,child)]=owner
        def restore():child.rmdir();outside.rename(child)
        before={name:state.path(name).read_bytes() for name in ('layout.json','source-reth.json','source-lighthouse.json')}
        for name,change,undo in [('foreign owner',owned((77,owner[1])),None),('foreign group',owned((owner[0],77)),None),
                                 ('another service account',owned(reth),None),('replaced directory',replace,restore)]:
            with self.subTest(name):
                change()
                try:
                    with self.assertRaisesRegex(ValueError,'original native child authority changed'):
                        self.f.request('upgrade-volume',filesystem=VOLUME)
                finally:
                    if undo:undo()
                    self.owners[key]=owner
                self.assertFalse(state.exists('volume.json'))
        self.assertTrue(self.f.request('upgrade-volume',filesystem=VOLUME)['upgraded'])
        self.assertFalse(any('start' in call or '--now' in call for call in self.f.calls))
        self.assertEqual(before,{name:state.path(name).read_bytes() for name in before})
        self.assertEqual(self.retained.read_bytes(),b'unchanged native data')

    def test_persistent_volume_fsync_failure_does_not_publish_helpers_or_start_on_retry(self):
        state=self.f.state;state.remove('volume.json');original=os.fsync;published=[]
        def failed(fd):
            if state.exists('volume.json') and stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('inert persistent volume persistence failure')
            original(fd)
        with patch.object(os,'fsync',side_effect=failed),patch.object(control.namespace,'publish',side_effect=lambda *_:published.append(True)):
            for _ in range(2):
                with self.assertRaises((ValueError,OSError)):self.f.request('upgrade-volume',filesystem=VOLUME)
            with self.assertRaises((ValueError,OSError)):control.ready(state,self.f.c)
        self.assertEqual(published,[]);self.assertFalse(any('start' in call for call in self.f.calls))
        self.assertTrue(self.f.request('upgrade-volume',filesystem=VOLUME)['upgraded'])

    def test_foreign_contract_cannot_stop_or_publish_volume_and_retirement_is_retained(self):
        self.f.state.remove('volume.json')
        with self.assertRaises(ValueError):control.dispatch(self.f.state,self.f.c,{'action':'upgrade-volume','contract':dict(self.f.c,owner='foreign'),'filesystem':VOLUME})
        self.assertEqual(self.f.calls,[]);self.assertFalse(self.f.state.exists('volume.json'))
        self.f.request('destroy');self.f.request('upgrade-volume',filesystem=VOLUME)
        self.assertTrue(self.f.state.halted()['retired'])

    def test_carried_upgrade_play_renders_exact_request_and_runs_only_the_actual_upgrade(self):
        try:
            import yaml
            from ansible.parsing.dataloader import DataLoader
            from ansible.template import Templar
        except ImportError:self.skipTest('pinned Ansible runtime required for actual template execution')
        self.f.state.remove('volume.json');self.renumber()
        root=Path(__file__).parents[1]/'templates'
        path=root/'ansible/eth-rpc/upgrade-volume.yml'
        tasks=yaml.safe_load(path.read_text())[0]['tasks']
        self.assertEqual(len(tasks),2)
        self.assertIn("eth_authority_request.action == 'upgrade-volume'",tasks[0]['ansible.builtin.assert']['that'])
        request={'action':'upgrade-volume','contract':self.f.c,'filesystem':VOLUME}
        variables={'eth_authority_request':request,'eth_authority_loader':'inert authenticated loader',
                   'playbook_dir':str(path.parent)}
        template=Templar(loader=DataLoader(),variables=variables)
        command=template.template(tasks[1]['ansible.builtin.command'])
        self.assertEqual(command['argv'][:4],['/usr/bin/python3','-I','-c','inert authenticated loader'])
        self.assertEqual(Path(command['argv'][4]).resolve(),(root/'authority/control.py').resolve())
        self.assertEqual(command['argv'][5],'request')
        value=json.loads(command['stdin']);self.assertEqual(value,request)
        result=control.dispatch(self.f.state,self.f.c,value)
        self.assertTrue(result['upgraded']);self.assertFalse(result['started'])
        self.assertFalse(any('start' in call or '--now' in call for call in self.f.calls))

    def test_actual_probe_parses_bounded_single_kernel_row_and_matches_open_descriptor(self):
        descriptor=layout.root_directory(self.root)
        try:
            info=os.fstat(descriptor);row={'uuid':VOLUME['uuid'],'fstype':'ext4','maj:min':f'{os.major(info.st_dev)}:{os.minor(info.st_dev)}','fsroot':'/'}
            def invoke(argv,**_):
                self.assertEqual(argv[:4],['/usr/bin/findmnt','--kernel','--first-only','--json'])
                self.assertIn(str(self.root),argv)
                return json.dumps({'filesystems':[row]}).encode()
            with patch.object(layout,'run',side_effect=invoke):self.assertEqual(REAL_PROBE(self.root,descriptor),VOLUME)
            for changed in [dict(row,**{'maj:min':'1:999'}),dict(row,fsroot='/foreign'),dict(row,fstype='tmpfs'),dict(row,uuid=None),dict(row,uuid='0'*36)]:
                with patch.object(layout,'run',return_value=json.dumps({'filesystems':[changed]}).encode()):
                    with self.assertRaises(ValueError):REAL_PROBE(self.root,descriptor)
            for raw in [b'{"filesystems":[],"filesystems":[]}',b'x'*16385,json.dumps({'filesystems':[row,row]}).encode()]:
                with patch.object(layout,'run',return_value=raw):
                    with self.assertRaises(ValueError):REAL_PROBE(self.root,descriptor)
        finally:os.close(descriptor)


class PendingInitialization(unittest.TestCase):
    def setUp(self):
        self.f=runtime.Runtime();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.f.state.remove('layout.json');self.root=self.f.root/'native'
        self.f.install(layout,'ROOTS',{'rpc':self.root});real=os.fstat;owners=self.owners={}
        def metadata(fd):
            info=real(fd);row=list(info);key=(info.st_dev,info.st_ino)
            if key in owners:row[4],row[5]=owners[key]
            return os.stat_result(row)
        def chown(fd,uid,gid):
            info=real(fd);runtime.fixtures.hold(self,fd);owners[(info.st_dev,info.st_ino)]=(uid,gid)
        self.f.install(os,'fstat',metadata);self.f.install(os,'fchown',chown)
        self.f.install(layout,'topology',lambda _:None);self.f.install(layout,'verify',REAL_VERIFY)
        original=self.f.state.put
        def before_completion(name,value):
            if name=='layout.json':raise OSError('inert original initialization interruption')
            return original(name,value)
        with patch.object(self.f.state,'put',side_effect=before_completion):
            with self.assertRaises(OSError):layout.prepare(self.f.state,self.f.c,self.f.plan)
        # Exact earlier schema: an original root binding/empty children exists,
        # but no completed layout or stable-volume receipt has been published.
        self.f.state.remove('volume.json')
        self.before=self.f.state.path('layout-intent.json').read_bytes()
        self.nss=list(self.f.fixture.calls)

    def test_original_pending_layout_upgrade_preserves_intent_and_resumes_without_recreating_accounts(self):
        for name in ('reth','lighthouse'):(self.root/name).rmdir()
        with self.assertRaisesRegex(ValueError,'independent-evidence'):self.f.request('reserve')
        result=self.f.request('upgrade-volume',filesystem=VOLUME)
        self.assertTrue(result['initialization_pending']);self.assertFalse(self.f.state.exists('layout.json'))
        self.assertEqual(self.before,self.f.state.path('layout-intent.json').read_bytes())
        self.f.request('prepare');REAL_VERIFY(self.f.state,self.f.c,self.f.plan)
        self.assertEqual(self.f.fixture.calls,self.nss)
        self.assertFalse(any('start' in call or '--now' in call for call in self.f.calls))

    def test_partial_children_remain_empty_and_original_through_failed_volume_persistence(self):
        original=os.fsync
        def fail(fd):
            if self.f.state.exists('volume.json') and stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('inert pending-volume persistence failure')
            original(fd)
        with patch.object(os,'fsync',side_effect=fail):
            for _ in range(2):
                with self.assertRaises((ValueError,OSError)):self.f.request('upgrade-volume',filesystem=VOLUME)
                self.assertFalse(self.f.state.exists('layout.json'))
                self.assertEqual(self.before,self.f.state.path('layout-intent.json').read_bytes())
        self.f.request('upgrade-volume',filesystem=VOLUME);self.f.request('prepare')
        self.assertEqual(self.f.fixture.calls,self.nss)

    def test_nonempty_unfinished_child_and_changed_uuid_are_not_adopted(self):
        with self.assertRaises(ValueError):self.f.request('upgrade-volume',filesystem=dict(VOLUME,uuid='22345678-1234-1234-1234-123456789abc'))
        marker=self.root/'reth'/'unowned';marker.write_bytes(b'preserve unknown original data')
        with self.assertRaises(ValueError):self.f.request('upgrade-volume',filesystem=VOLUME)
        self.assertEqual(marker.read_bytes(),b'preserve unknown original data');self.assertFalse(self.f.state.exists('volume.json'))

    def refuses_upgrade(self,message):
        with self.assertRaisesRegex(ValueError,message):self.f.request('upgrade-volume',filesystem=VOLUME)
        self.assertFalse(self.f.state.exists('volume.json'));self.assertFalse(self.f.state.exists('layout.json'))
        self.assertEqual(self.before,self.f.state.path('layout-intent.json').read_bytes())

    def test_unfinished_child_with_another_owner_is_not_an_original_preparation(self):
        key=runtime.fixtures.held(self,self.root/'reth');owner=self.owners[key]
        other=self.owners[runtime.fixtures.held(self,self.root/'lighthouse')]
        for value in [(77,owner[1]),(owner[0],77),other]:
            with self.subTest(owner=value):
                self.owners[key]=value
                try:self.refuses_upgrade('incomplete native child is not an empty original preparation')
                finally:self.owners[key]=owner
        self.assertTrue(self.f.request('upgrade-volume',filesystem=VOLUME)['initialization_pending'])
        self.assertEqual(self.f.fixture.calls,self.nss)

    def test_replacement_root_never_takes_over_an_unfinished_preparation(self):
        retained=self.f.root/'retained-native';self.root.rename(retained);self.root.mkdir(mode=0o755)
        try:self.refuses_upgrade('original data directory inode or permissions changed')
        finally:self.root.rmdir();retained.rename(self.root)
        self.assertTrue(self.f.request('upgrade-volume',filesystem=VOLUME)['initialization_pending'])


if __name__=='__main__':unittest.main()

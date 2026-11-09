# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual fd traversal and mount parser with modeled filesystem capacity; no mounts."""
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parents[1]/'templates/authority'))
import eth_layout as layout


class Capacity(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);self.addCleanup(patch.stopall)
        self.root=Path(temporary.name).resolve();self.data=self.root/'native';self.data.mkdir()
        for name in ('reth','lighthouse'):(self.data/name).mkdir(mode=0o700)
        self.db=self.data/'reth'/'inert-database';self.db.write_bytes(b'inert actual allocated blocks')
        self.mounts=self.root/'mountinfo';self.mounts.write_text('20 1 8:1 / / rw - ext4 /dev/inert rw\n')
        self.contract={'role':'rpc','kind':'full'};self.plan={};self.free=1500*10**9
        patch.object(layout,'ROOTS',{'rpc':self.data}).start();patch.object(layout,'MOUNTS',self.mounts).start()
        patch.object(layout,'verify').start()
        patch.object(layout,'root_directory',side_effect=lambda path:os.open(path,layout.FLAGS)).start()
        patch.object(layout,'open_native',side_effect=lambda _s,_c,_a,name:os.open(self.data/name,layout.FLAGS)).start()
        patch.object(os,'fstatvfs',side_effect=lambda _:SimpleNamespace(f_bavail=self.free,f_frsize=1)).start()

    def capacity(self):return layout.capacity(None,self.contract,self.plan)

    def test_initial_free_space_cannot_be_replaced_by_total_capacity_or_a_completion_marker(self):
        self.free=1499*10**9
        (self.data/'reth'/'.erpc-snapshot-done').write_text('inert legacy marker')
        with self.assertRaises(ValueError):self.capacity()
        self.free=1500*10**9;result=self.capacity()
        self.assertLess(result['allocated_bytes'],1000000);self.assertGreater(result['required_free_bytes'],1499*10**9)

    def test_real_allocation_offsets_remaining_sync_but_never_operational_headroom(self):
        real=os.stat
        class Metadata:
            def __init__(self,value):self.value=value
            def __getattr__(self,name):return getattr(self.value,name)
            @property
            def st_blocks(self):return 1400*10**9//512
        def accounting(path,*args,**kwargs):
            value=real(path,*args,**kwargs)
            return Metadata(value) if path=='inert-database' else value
        with patch.object(os,'stat',side_effect=accounting):
            self.free=199*10**9
            with self.assertRaises(ValueError):self.capacity()
            self.free=200*10**9;self.assertEqual(self.capacity()['required_free_bytes'],200*10**9)

    def test_same_device_bind_and_deep_database_mounts_are_refused(self):
        for mount in [self.data/'reth',self.data/'reth'/'db',self.data/'lighthouse'/'beacon'/'chain_db']:
            self.mounts.write_text(f'20 1 8:1 / / rw - ext4 /dev/inert rw\n21 20 8:1 / {mount} rw - ext4 /dev/inert rw\n')
            with self.assertRaises(ValueError):self.capacity()
        self.mounts.write_text(f'20 1 8:1 / / rw - ext4 /dev/inert rw\n21 20 8:2 / {self.data} rw - ext4 /dev/inert2 rw\n')
        self.capacity()

    def test_native_symlink_never_counts_or_traverses_an_unrelated_directory(self):
        outside=self.root/'outside';outside.mkdir();(outside/'sentinel').write_bytes(b'unchanged')
        (self.data/'reth'/'indirect').symlink_to(outside)
        with self.assertRaises(ValueError):self.capacity()
        self.assertEqual((outside/'sentinel').read_bytes(),b'unchanged')


if __name__=='__main__':unittest.main()

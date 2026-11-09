#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual carried preflight -> dispatcher -> storage qualification composition.

Only OS/NSS/service/mount observations are inert. The dispatcher, fresh-layout
checks, descriptor reads and sealed public result publication execute unchanged.
"""
import json
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests'))
sys.path.insert(0,str(ROOT.parent/'erpc-chain-rollup/templates/scripts'))
from validator_host import Host
import control
import host
import installer
import state


class Preflight(unittest.TestCase):
    def setUp(self):
        self.fixture=Host();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root;self.runs=self.root/'runs'
        patch.object(installer,'RUNS',self.runs).start()
        original_fresh,original_preflight=host.fresh,host.preflight
        patch.object(host,'fresh',side_effect=lambda:original_fresh(run=self.fixture.command)).start()
        patch.object(host,'preflight',side_effect=lambda:original_preflight(run=self.fixture.command)).start()

    def snapshot(self,root):
        if not root.exists() and not root.is_symlink():return None
        result={}
        paths=[root]
        if not root.is_symlink():paths+=list(root.rglob('*'))
        for path in paths:
            info=path.lstat()
            content=os.readlink(path) if path.is_symlink() else path.read_bytes() if stat.S_ISREG(info.st_mode) else None
            result[str(path.relative_to(root))]=(info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,content)
        return result

    def source(self,index):
        run=self.runs/('r-preflight-layout-'+str(index));source=run/'bundle/validator/node';source.mkdir(parents=True)
        for path in (ROOT/'templates/validator/node').glob('*.py'):
            (source/path.name).write_bytes(path.read_bytes())
        (source/'upstreams.py').write_bytes((ROOT.parent/'erpc-chain-rollup/templates/scripts/upstreams.py').read_bytes())
        (run/'bundle.tar.gz').write_bytes(b'inert submitted bundle bytes')
        return source,run/'validator-public-result.json'

    def probe(self,index,root):
        source,result=self.source(index)
        before=self.snapshot(root)
        with patch.object(host,'ROOT',root),patch.object(host,'DATA',root/'data'):
            answer=installer.play(['play-control'],{'action':'preflight'},source)
        self.assertTrue(answer['public_result_written'])
        published=json.loads(result.read_bytes())
        self.assertEqual(published['result']['data_uuid'],self.fixture.uuid)
        self.assertEqual(published['result']['free_bytes'],host.BUDGET)
        self.assertEqual(self.snapshot(root),before)
        self.assertEqual(self.fixture.fixture.calls,[])
        self.assertFalse((root/'owner.json').exists())

    def test_actual_carried_fresh_probe_accepts_prepared_storage_without_reserving_any_owner(self):
        layouts=[None,(),('lost+found',),('data',),('data','data/lost+found'),('data','lost+found','data/lost+found')]
        for index,layout in enumerate(layouts):
            with self.subTest(layout=layout):
                root=self.root/('volume-'+str(index))
                if layout is not None:
                    root.mkdir(mode=0o755)
                    for name in layout:(root/name).mkdir(mode=0o700)
                self.probe(index,root)

    def test_actual_dispatch_refuses_existing_owners_unknown_history_and_unsafe_links(self):
        for index,kind in enumerate(('owner','unknown','native-data','recovery-data','data-link','recovery-link','writable'),20):
            with self.subTest(kind=kind):
                root=self.root/('refuse-'+kind);root.mkdir(mode=0o755)
                if kind=='owner':state.State(root).reserve(self.fixture.contract)
                elif kind=='unknown':(root/'unknown-record').write_text('retain unknown ownership')
                elif kind=='native-data':(root/'data').mkdir();(root/'data/block').write_text('retain original history')
                elif kind=='recovery-data':(root/'lost+found').mkdir();(root/'lost+found/recovered').write_text('retain filesystem recovery')
                elif kind=='data-link':(root/'data').symlink_to(self.root,target_is_directory=True)
                elif kind=='recovery-link':(root/'lost+found').symlink_to(self.root,target_is_directory=True)
                else:root.chmod(0o777)
                source,result=self.source(index);before=self.snapshot(root)
                with patch.object(host,'ROOT',root),patch.object(host,'DATA',root/'data'):
                    with self.assertRaises((ValueError,OSError)):
                        installer.play(['play-control'],{'action':'preflight'},source)
                self.assertFalse(result.exists())
                self.assertEqual(self.snapshot(root),before)
                self.assertEqual(self.fixture.fixture.calls,[])


if __name__=='__main__':
    suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(Preflight))
    raise SystemExit(not unittest.TextTestRunner().run(suite).wasSuccessful())

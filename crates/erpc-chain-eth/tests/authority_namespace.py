# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual immutable helper publication; only root ownership is projected in fixtures."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import authority_accounts as fixtures
import eth_namespace as namespace


class Publication(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.Accounts();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        f=self.fixture;self.root=f.root;source=self.root/'source';source.mkdir()
        for name in namespace.RPC_FILES:(source/name).write_bytes((namespace.SOURCE/name).read_bytes())
        f.install(namespace,'SOURCE',source)
        profile={key:self.root/key for key in ('config','opt','helpers','firewall')};profile['units']=('reth.service','lighthouse.service','reth-snapshot.service','erpc-eth-firewall.service')
        f.install(namespace,'PROFILES',{'rpc':profile});f.install(namespace,'SYSTEMD',self.root/'units');(self.root/'units').mkdir()
        f.install(namespace,'COMMON_FIREWALL',self.root/'common.py');f.install(namespace,'TUNING',(self.root/'tuning'/'90.conf',))
        actual=os.lstat;scan=os.scandir
        def metadata(path,*args,**kwargs):
            value=list(actual(path,*args,**kwargs));candidate=Path(path)
            value[4]=77 if (value[2],value[1]) in f.foreign else 0
            if candidate in self.root.parents:value[0]&=~0o022
            return os.stat_result(value)
        f.install(os,'lstat',metadata);f.install(Path,'lstat',lambda path:metadata(path))
        class Entry:
            def __init__(self,original):self.original=original
            def __getattr__(self,name):return getattr(self.original,name)
            def stat(self,*,follow_symlinks=True):return metadata(self.original.path)
        class Entries(list):
            def __enter__(self):return self
            def __exit__(self,*_):return False
        def entries(path):
            with scan(path) as values:return Entries(Entry(item) for item in values)
        # Preserve both scandir iteration styles used by the canonical loader and
        # pathlib across the supported Python versions.
        f.install(os,'scandir',entries)

    def test_actual_publication_is_hash_bound_readable_under_private_umask_and_repeatable(self):
        previous=os.umask(0o077)
        try:revision=namespace.publish('rpc');self.assertEqual(namespace.publish('rpc'),revision)
        finally:os.umask(previous)
        selected=namespace.PROFILES['rpc']['helpers']/'releases'/revision
        self.assertEqual(selected.stat().st_mode&0o777,0o755)
        for name in namespace.RPC_FILES:self.assertEqual((selected/name).stat().st_mode&0o777,0o444)
        self.assertEqual(namespace.trusted_release(str(namespace.PROFILES['rpc']['helpers']),[list(namespace.RPC_FILES)]),str(selected))

    def test_unknown_boot_override_or_writable_namespace_refuses_without_repair(self):
        override=namespace.SYSTEMD/'reth.service.d';override.mkdir();bad=override/'99-unmanaged.conf';bad.write_text('original unrelated override')
        with self.assertRaises(ValueError):namespace.publish('rpc')
        self.assertEqual(bad.read_text(),'original unrelated override');bad.unlink();override.rmdir()
        helpers=namespace.PROFILES['rpc']['helpers'];helpers.mkdir(mode=0o777);helpers.chmod(0o777)
        with self.assertRaises(ValueError):namespace.publish('rpc')
        self.assertEqual(helpers.stat().st_mode&0o777,0o777)

    def test_foreign_or_indirect_current_source_cannot_be_adopted(self):
        revision=namespace.publish('rpc');selected=namespace.PROFILES['rpc']['helpers']/'releases'/revision
        file=selected/'control.py';file.chmod(0o644);outside=self.root/'outside';file.rename(outside);file.symlink_to(outside)
        with self.assertRaises(ValueError):namespace.publish('rpc')
        self.assertTrue(file.is_symlink());self.assertTrue(outside.exists())

    def test_new_cli_finishes_only_the_valid_original_pending_pointer_and_retains_both_revisions(self):
        old=namespace.publish('rpc');helpers=namespace.PROFILES['rpc']['helpers'];previous=helpers/'releases'/old
        (helpers/'current.pending').symlink_to(previous)
        source=namespace.SOURCE/'control.py';source.write_bytes(source.read_bytes()+b'\n# inert later source revision\n')
        current=namespace.publish('rpc')
        self.assertNotEqual(current,old);self.assertTrue(previous.is_dir())
        self.assertEqual(os.readlink(helpers/'current'),str(helpers/'releases'/current))


if __name__=='__main__':unittest.main()

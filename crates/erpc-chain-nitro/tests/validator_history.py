#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert original database layout and interrupted history-publication fixtures."""
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/validator/node'))
import history
import host
import state
import storage
import volumes
import json


class History(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup); self.addCleanup(patch.stopall)
        self.root = Path(tmp.name).resolve()
        patch.object(storage, 'ROOT_UID', os.getuid()).start(); patch.object(storage, 'TRUST_ANCHOR', self.root).start()
        patch.object(host, 'ROOT', self.root/'state').start()
        patch.object(host, 'DATA', host.ROOT/'data').start()
        self.account = {'uid': os.getuid(), 'gid': os.getgid()}
        self.expected = {'owner': 'a'*26, 'family': 'arbitrum', 'network': 'mainnet', 'platform': 'amd64',
                         'role': 'assertion-validator', 'wallet': '0x'+'1'*40, 'creation': 'b'*32,
                         'host_binding': 'c'*64, 'data_uuid': '00000000-0000-0000-0000-000000000001'}
        self.expected = getattr(self,'expected_override',self.expected)
        self.state = state.State(self.root/'state'); storage.directory(self.state.root, create=True)
        self.state.reserve(self.expected)
        def filesystem_command(argv,**kwargs):
            if '--submounts' in argv: return json.dumps({'filesystems':[{'target':str(host.ROOT)}]}).encode()
            return json.dumps({'filesystems':[{'uuid':self.expected['data_uuid'],'fstype':'ext4','options':'rw'}]}).encode()
        patch.object(host,'command',side_effect=filesystem_command).start()
        host.reserve_layout(self.state,self.expected,filesystem_command)
        host.DATA.mkdir(mode=0o700)
        self.state.put('data.json',{'contract':self.expected,**self.account,'directory':volumes.stable(host.DATA.lstat())})
        self.node = host.DATA/'chain/nitro'; self.node.mkdir(parents=True)
        for name in history.DBS:
            path = self.node/name; path.mkdir()
            (path/'marker.manifest.000007.MANIFEST-000010').touch()
            (path/'MANIFEST-000010').write_text('inert database manifest, not a native database')
        freezer=self.node/'l2chaindata/ancient/chain-tip-block-records';freezer.mkdir(parents=True)
        (freezer/'records.cidx').write_bytes(b'INERT INDEX');(freezer/'records.meta').write_bytes(b'INERT META')
        (host.DATA/'chain/nodekey').write_text('inert original node identity')
        (host.DATA/'jwtsecret').write_text('inert original validation identity')
        self.origin = {'public': 'inert original wallet receipt'}
        self.observed = {'phase': 'observing', 'local_validation_ready': True,
                         'validated_block_hash': '0x'+'a'*64, 'wasm_module_root': '0x'+'b'*64}
        self.quiet = lambda: None

    def activate(self): return history.activate(self.state, self.expected, self.account, self.origin, self.quiet, self.observed)

    def test_retained_original_history_allows_native_manifest_progress(self):
        original = self.activate()
        path = self.node/'arbitrumdata'
        (path/'marker.manifest.000008.MANIFEST-000011').touch(); (path/'MANIFEST-000011').write_text('inert next native manifest')
        history.verify(self.state, self.expected, self.account, self.quiet)
        history.retain(self.state, self.expected, self.account, self.quiet)
        saved = self.state.get('signer-activated.json')
        self.assertEqual(saved['history']['databases']['arbitrumdata']['minimum_sequence'], 8)
        self.assertEqual(saved['origin'], original['origin'])
        (path/'marker.manifest.000008.MANIFEST-000011').unlink()
        with self.assertRaisesRegex(ValueError, 'regressed'): history.verify(self.state, self.expected, self.account, self.quiet)

    def test_replaced_database_or_native_identity_refuses_before_any_repair(self):
        self.activate(); path = self.node/'arbitrumdata'; path.rename(self.node/'retained-old-database'); path.mkdir()
        (path/'marker.manifest.000007.MANIFEST-000010').touch(); (path/'MANIFEST-000010').write_text('inert copied manifest')
        with self.assertRaisesRegex(ValueError, 'replaced'): history.verify(self.state, self.expected, self.account, self.quiet)
        self.assertTrue((self.node/'retained-old-database').exists())
        path.rename(self.node/'unowned-replacement'); (self.node/'retained-old-database').rename(path)
        (host.DATA/'jwtsecret').write_text('inert unexpected replacement')
        with self.assertRaisesRegex(ValueError, 'identities'): history.verify(self.state, self.expected, self.account, self.quiet)

    def test_missing_manifest_symlink_or_unknown_format_never_authorizes_recreation(self):
        path = self.node/'arbitrumdata'; marker = path/'marker.manifest.000007.MANIFEST-000010'
        marker.unlink()
        with self.assertRaises(FileNotFoundError): self.activate()
        (path/'CURRENT').write_text('MANIFEST-000010\n')
        self.assertEqual(self.activate()['history']['databases']['arbitrumdata']['format'], 'current')
        (path/'MANIFEST-000010').rename(self.root/'outside-manifest')
        (path/'MANIFEST-000010').symlink_to(self.root/'outside-manifest')
        with self.assertRaises(ValueError): history.verify(self.state, self.expected, self.account, self.quiet)

    def test_missing_persistent_validation_freezer_cannot_be_recreated_for_an_active_key(self):
        self.activate();freezer=self.node/'l2chaindata/ancient/chain-tip-block-records'
        (freezer/'records.cidx').unlink()
        with self.assertRaises(FileNotFoundError):history.verify(self.state,self.expected,self.account,self.quiet)
        self.assertFalse((freezer/'records.cidx').exists())

    def test_failed_directory_sync_and_failed_drain_do_not_publish_activation(self):
        with patch.object(history, 'sync_directory', side_effect=OSError('inert fsync failure')):
            with self.assertRaises(OSError): self.activate()
        self.assertFalse((self.state.root/'signer-activated.json').exists())
        self.quiet = lambda: (_ for _ in ()).throw(ValueError('inert retained writer'))
        with self.assertRaisesRegex(ValueError, 'writer'): self.activate()
        self.assertFalse((self.state.root/'signer-activated.json').exists())


if __name__ == '__main__': unittest.main()

#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual validator entry + common controller with inert nft/systemd fixtures."""
import builtins
import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/validator/node'))
sys.path.insert(0,str(ROOT.parent/'erpc-chain-rollup/templates/scripts'))
spec=importlib.util.spec_from_file_location('common_fixture',ROOT.parent/'erpc-ops/tests/firewall.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
import control
import host
import runtime
import storage


class Firewall(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        self.fixture=fixture.FirewallTests();self.fixture.family='arbitrum';self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root.resolve()
        patch.object(storage,'ROOT_UID',os.getuid()).start();patch.object(storage,'TRUST_ANCHOR',self.root).start()
        for name,value in {'ROOT':self.root/'state','CONFIG':self.root/'config','RUNTIME':self.root/'run',
                           'FIREWALL_HELPER':self.root/'helper.py'}.items():patch.object(host,name,value).start()
        patch.object(host,'namespaces').start()
        self.expected={'owner':'a'*26,'family':'arbitrum','network':'mainnet','platform':'amd64',
                       'role':'assertion-validator','wallet':'0x'+'1'*40,'creation':'b'*32,
                       'host_binding':'c'*64,'data_uuid':'00000000-0000-0000-0000-000000000001'}
        storage.directory(host.ROOT,create=True);storage.directory(host.CONFIG,create=True)
        self.controller=control.Control(self.expected);self.controller.state.reserve(self.expected)
        storage.write(host.CONFIG/'contract.json',storage.encode(self.expected))
        raw=(ROOT.parent/'erpc-ops/templates/rpc-firewall.py').read_bytes()
        storage.write(host.FIREWALL_HELPER,raw)
        self.controller.state.put('common-firewall.json',{'contract':self.expected,'sha256':hashlib.sha256(raw).hexdigest()})
        def fixture_exec(code,namespace):
            builtins.exec(code,namespace)
            # Same shipped class/dispatch; only constructor filesystem and inert
            # command boundaries are supplied by the shared regression fixture.
            namespace['Firewall']=lambda family:self.fixture.control
        patch.object(runtime,'exec',side_effect=fixture_exec,create=True).start()

    def test_actual_cold_boot_entry_uses_one_common_lock_and_reloads_confirmed_policy(self):
        operation,bundle=self.fixture.apply('a','inert original policy')
        runtime.common(self.controller.state,self.expected,'confirm',operation,bundle)
        self.fixture.live=None;self.fixture.calls.clear()
        with patch.object(sys,'argv',['control.py','firewall-load']),patch.object(control.resource,'setrlimit'):
            control.main()
        self.assertEqual(self.fixture.live,'inert original policy')
        self.assertEqual(sum(call[:2]==['nft','-f'] for call in self.fixture.calls),1)
        self.assertTrue(host.RUNTIME.is_dir())

    def test_confirm_acknowledgement_cannot_corrupt_controller_json_stdout(self):
        operation,bundle=self.fixture.apply('a','inert original policy')
        output=io.StringIO()
        with contextlib.redirect_stdout(output):runtime.common(self.controller.state,self.expected,'confirm',operation,bundle)
        self.assertEqual(output.getvalue(),'')

    def test_superseded_receipt_and_modified_common_helper_cannot_confirm(self):
        old_operation,old_bundle=self.fixture.apply('a','inert original policy')
        self.fixture.apply('b','inert newer policy')
        with self.assertRaises(ValueError):runtime.common(self.controller.state,self.expected,'confirm',old_operation,old_bundle)
        host.FIREWALL_HELPER.write_bytes(host.FIREWALL_HELPER.read_bytes()+b'\n# inert substitution\n')
        calls=len(self.fixture.calls)
        with self.assertRaisesRegex(ValueError,'differs'):runtime.common(self.controller.state,self.expected,'load')
        self.assertEqual(len(self.fixture.calls),calls)


if __name__=='__main__':unittest.main()

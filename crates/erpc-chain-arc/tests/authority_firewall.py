#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual Arc boot-controller/common-firewall composition and its single lock owner."""
import contextlib
import fcntl
import importlib.util
import io
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import authority_lifecycle as lifecycle
import control
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('arc_common_fixture',ROOT.parent/'erpc-ops/tests/firewall.py')
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)


class Boot(unittest.TestCase):
    def setUp(self):
        self.f=lifecycle.Lifecycle('runTest');self.f.setUp()
        self.c=self.f.c
        self.fx=common.FirewallTests('runTest');self.fx.family='arc';self.fx.setUp()
        self.fx.root=self.f.root;self.fx.control=self.fx.module.Firewall('arc',self.f.root,self.fx.command)
        source=(ROOT.parent/'erpc-ops/templates/rpc-firewall.py').read_text().replace('ROOT_UID = 0','ROOT_UID = '+str(os.getuid()))
        self.c.write_bytes('/usr/local/lib/erpc/rpc-firewall.py',source.encode(),0o700)
        self.c.run=self.fx.command
        token=self.fx.apply('aaaaaa','inert-original-policy')
        self.fx.control.dispatch('confirm',*token)
        self.fx.calls.clear()
        self.real_common=patch.object(lifecycle.Model,'common',control.Control.common);self.real_common.start()
    def tearDown(self):self.real_common.stop();self.fx.doCleanups();self.f.tearDown()
    def invoke(self):
        with patch.object(control,'Control',lambda:self.c),patch.object(sys,'argv',['control.py','firewall-load','firewall']),contextlib.redirect_stderr(io.StringIO()):
            return control.main()
    def test_cold_and_live_boot_reaches_real_common_dispatch_without_a_second_lock(self):
        self.fx.live=None
        self.assertEqual(self.invoke(),0)
        self.assertEqual(self.fx.live,'inert-original-policy')
        calls=sum(row[:2]==['nft','-f'] for row in self.fx.calls)
        self.assertEqual(calls,1)
        self.assertEqual(self.invoke(),0)
        self.assertEqual(sum(row[:2]==['nft','-f'] for row in self.fx.calls),1)
    def test_competing_lock_or_untrusted_helper_never_removes_or_changes_policy(self):
        self.fx.live=None
        fd=os.open(self.c.path('/opt/erpc'),os.O_RDONLY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
            self.assertNotEqual(self.invoke(),0)
        finally:os.close(fd)
        self.assertIsNone(self.fx.live)
        self.c.path('/usr/local/lib/erpc/rpc-firewall.py').chmod(0o666)
        self.assertNotEqual(self.invoke(),0)
        self.assertIsNone(self.fx.live)


if __name__=='__main__':unittest.main()

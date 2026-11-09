# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real controller/common cold-boot composition, with only nft/systemd effects inert."""
import fcntl
import importlib.util
import os
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

a=load('avax_authority_case',Path(__file__).with_name('authority.py'))
f=load('common_firewall_case',ROOT.parent/'erpc-ops/tests/firewall.py')

class Composed(unittest.TestCase):
    def setUp(self):
        self.a=a.Authority();self.a.setUp();self.addCleanup(self.a.doCleanups)
        self.a.c.prepare(self.a.expected)
        self.f=f.AvalancheTests();self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.f.root=self.a.root;self.f.control=self.f.module.Firewall('avax',self.a.root,self.f.command)
        self.f.control.directory.mkdir(parents=True)
        self.f.control.path('/opt/erpc/runs').mkdir(parents=True)
        self.helper=self.a.root/'usr/local/lib/erpc/rpc-firewall.py';self.helper.parent.mkdir(parents=True)
        source=(ROOT.parent/'erpc-ops/templates/rpc-firewall.py').read_text().replace('ROOT_UID = 0','ROOT_UID = '+str(os.getuid()))
        self.helper.write_text(source);self.helper.chmod(0o644)
        self.a.c.run=self.f.command
        token=self.f.apply('aaaaaa','fixture-initial-policy')
        self.f.control.dispatch('confirm',*token)
        self.f.calls.clear()

    def test_cold_and_live_policy_load_through_real_controller_and_real_common_lock(self):
        self.f.live=None
        self.a.c.dispatch({'action':'firewall-load','contract':self.a.expected})
        self.assertEqual(self.f.live,'fixture-initial-policy')
        applied=sum(call[:2]==['nft','-f'] for call in self.f.calls)
        self.assertEqual(applied,1)
        self.a.c.dispatch({'action':'firewall-load','contract':self.a.expected})
        self.assertEqual(sum(call[:2]==['nft','-f'] for call in self.f.calls),1)

    def test_competing_lock_or_wrong_scope_or_unsafe_helper_cannot_restore_policy(self):
        self.f.live=None
        fd=os.open(self.a.root/'opt/erpc',os.O_RDONLY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX)
            with self.assertRaises(BlockingIOError):self.a.c.dispatch({'action':'firewall-load','contract':self.a.expected})
        finally:os.close(fd)
        self.assertIsNone(self.f.live)
        with self.assertRaises(ValueError):self.a.c.dispatch({'action':'firewall-load','contract':dict(self.a.expected,network='mainnet')})
        self.helper.chmod(0o666)
        with self.assertRaises(ValueError):self.a.c.dispatch({'action':'firewall-load','contract':self.a.expected})
        self.assertIsNone(self.f.live)

if __name__=='__main__':unittest.main()

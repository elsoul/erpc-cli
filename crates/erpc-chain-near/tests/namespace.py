# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real inert filesystem authority checks; expected root UID modeled locally."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('near_namespace', Path(__file__).parents[1] / 'templates/node/control.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
c.ROOT_UID = os.getuid()

class Namespace(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.control = c.Control(self.root)
        mocked = patch.object(self.control, 'account_snapshot', return_value=([], [])); mocked.start(); self.addCleanup(mocked.stop)
        mocked = patch.object(self.control, 'account', return_value=(20000, 20000)); mocked.start(); self.addCleanup(mocked.stop)
        self.expected = {'owner': 'fixture', 'network': 'testnet', 'role': 'rpc',
                         'genesis_hash': c.PINS['testnet']['genesis_hash']}

    def test_unsafe_missing_destination_ancestors_are_not_repaired_or_reserved(self):
        for path in ('/etc/erpc', '/usr/local/lib/erpc', '/etc/near', '/etc/systemd/system', '/etc/credstore.encrypted'):
            with self.subTest(path=path):
                directory = self.control.path(path)
                directory.mkdir(parents=True, exist_ok=True)
                directory.chmod(0o777)
                with self.assertRaises(c.Refused): self.control.reserve(self.expected)
                self.assertEqual(directory.stat().st_mode & 0o777, 0o777)
                self.assertFalse((self.control.directory / 'contract.json').exists())
                directory.chmod(0o755)

    def test_foreign_directory_owner_is_not_adopted(self):
        directory = self.control.directory
        directory.mkdir(parents=True)
        original = c.Path.lstat
        def metadata(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            if path == directory:
                values = list(info); values[4] = os.getuid() + 1
                return os.stat_result(values)
            return info
        with patch.object(c.Path, 'lstat', metadata):
            with self.assertRaises(c.Refused): self.control.reserve(self.expected)
        self.assertFalse((directory / 'contract.json').exists())

    def test_initial_symlink_or_unknown_unit_never_gets_an_owner(self):
        for unit in ('near-node.service', 'erpc-near-firewall.service'):
            file = self.control.path('/etc/systemd/system/' + unit)
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text('inert')
            with self.assertRaises(c.Refused): self.control.reserve(self.expected)
            file.unlink()
            dropin = file.with_name(file.name + '.d'); dropin.mkdir()
            with self.assertRaises(c.Refused): self.control.reserve(self.expected)
            dropin.rmdir()
        outside = self.root / 'outside'; outside.mkdir()
        self.control.directory.parent.mkdir(parents=True, exist_ok=True)
        self.control.directory.symlink_to(outside)
        with self.assertRaises(c.Refused): self.control.reserve(self.expected)
        self.assertEqual(list(outside.iterdir()), [])

    def test_owner_reads_and_overwrites_reject_public_writable_linked_or_indirect_state(self):
        self.control.reserve(self.expected)
        file = self.control.directory / 'contract.json'
        raw = file.read_bytes()
        for mode in (0o644, 0o666, 0o620):
            file.chmod(mode)
            for operation in (lambda: self.control.read('contract.json'),
                              lambda: self.control.write('contract.json', self.expected),
                              lambda: self.control.remove('contract.json')):
                with self.assertRaises(c.Refused): operation()
            self.assertEqual(file.read_bytes(), raw)
        file.chmod(0o600)
        alias = self.root / 'alias'; os.link(file, alias)
        with self.assertRaises(c.Refused): self.control.read('contract.json')
        alias.unlink()
        file.rename(alias); file.symlink_to(alias)
        with self.assertRaises((c.Refused, OSError)): self.control.read('contract.json')
        self.assertEqual(alias.read_bytes(), raw)

    def test_fifo_and_oversized_receipt_do_not_block_or_parse(self):
        self.control.reserve(self.expected)
        file = self.control.directory / 'receipt.json'
        os.mkfifo(file, 0o600)
        with self.assertRaises(c.Refused): self.control.read(file.name)
        file.unlink(); file.write_bytes(b' ' * 65537); file.chmod(0o600)
        with self.assertRaises(c.Refused): self.control.read(file.name)
        for name in ('../outside', '/outside', '..', '.pending', 'x/y'):
            with self.assertRaises(c.Refused): self.control.write(name, {})

    def test_unknown_or_unsafe_dropins_refuse_existing_owner(self):
        self.control.reserve(self.expected)
        for unit in ('near-node.service', 'erpc-near-firewall.service'):
            directory = self.control.path('/etc/systemd/system/' + unit + '.d')
            directory.mkdir(parents=True)
            foreign = directory / '99-foreign.conf'; foreign.write_text('inert')
            with self.assertRaises(c.Refused): self.control.contract(self.expected)
            foreign.unlink()
            guard = directory / '50-erpc-firewall-guard.conf'; guard.write_text('inert controlled fixture')
            self.control.contract(self.expected)
            guard.chmod(0o666)
            with self.assertRaises(c.Refused): self.control.contract(self.expected)
            guard.chmod(0o644)
            alias = self.root / 'alias'; os.link(guard, alias)
            with self.assertRaises(c.Refused): self.control.contract(self.expected)
            alias.unlink(); guard.unlink(); guard.mkdir()
            with self.assertRaises(c.Refused): self.control.contract(self.expected)
            guard.rmdir(); directory.rmdir()

    def test_helpers_and_config_trees_do_not_trust_nested_links_or_mutable_files(self):
        self.control.reserve(self.expected)
        for path in (c.HELPERS, '/etc/near'):
            directory = self.control.path(path); directory.mkdir(parents=True)
            nested = directory / 'nested'; nested.mkdir()
            file = nested / 'fixture'; file.write_text('inert')
            self.control.contract(self.expected)
            file.chmod(0o666)
            with self.assertRaises(c.Refused): self.control.contract(self.expected)
            file.chmod(0o644); file.unlink(); file.symlink_to(self.root)
            with self.assertRaises(c.Refused): self.control.contract(self.expected)
            file.unlink()

    def test_common_guard_interruption_remains_retryable_and_does_not_block_owned_stop(self):
        path = Path(__file__).parents[2] / 'erpc-ops/templates/rpc-firewall.py'
        spec = importlib.util.spec_from_file_location('near_common_firewall', path)
        common = importlib.util.module_from_spec(spec); spec.loader.exec_module(common)
        common.ROOT_UID = os.getuid()
        self.control.reserve(self.expected)
        self.control.path('/opt/erpc').mkdir(parents=True)
        calls = []
        def host(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, b'loaded' if argv[:2] == ['systemctl', 'show'] else b'', b'')
        firewall = common.Firewall('near', self.root, host)
        with patch.object(common.os, 'fsync', side_effect=OSError('inert interrupted guard publication')):
            with self.assertRaises(OSError): firewall.prepare_guards()
        pending = self.control.path('/etc/systemd/system/near-node.service.d/50-erpc-firewall-guard.conf.new')
        self.assertTrue(pending.exists())
        self.assertEqual(pending.stat().st_mode & 0o777, 0o644)
        self.control.contract(self.expected)
        with patch.object(self.control, 'container', return_value=None), patch.object(self.control, 'run', side_effect=host):
            self.control.dispatch('stop', self.expected)
        self.assertIn(['systemctl', 'stop', 'near-node.service'], calls)
        firewall.prepare_guards()
        self.assertFalse(pending.exists())
        firewall.require_guards()
        self.control.contract(self.expected)
        # The additional accepted name carries the same real file restrictions.
        pending.write_text('inert pending bytes'); pending.chmod(0o666)
        with self.assertRaises(c.Refused): self.control.contract(self.expected)
        pending.chmod(0o644)
        alias = self.root / 'alias'; os.link(pending, alias)
        with self.assertRaises(c.Refused): self.control.contract(self.expected)
        alias.unlink(); pending.unlink(); pending.symlink_to(self.root)
        with self.assertRaises(c.Refused): self.control.contract(self.expected)
        pending.unlink(); pending.mkdir()
        with self.assertRaises(c.Refused): self.control.contract(self.expected)

    def test_rpc_disabled_key_path_cannot_supply_an_implicit_validator(self):
        self.control.reserve(self.expected)
        file = self.control.path('/etc/near/disabled-validator.json')
        file.parent.mkdir(parents=True); file.write_text('inert key-shaped fixture')
        with self.assertRaisesRegex(c.Refused, 'cannot adopt a validator'): self.control.contract(self.expected)

    def test_checked_firewall_bridge_uses_only_the_protected_common_file(self):
        self.control.reserve(self.expected)
        file = self.control.path('/usr/local/lib/erpc/rpc-firewall.py')
        file.parent.mkdir(parents=True)
        file.write_text("class Firewall:\n def __init__(self, family): self.family=family\n def dispatch(self,*args): return (self.family, args)\n")
        self.assertEqual(self.control.firewall_action('load'), ('near', ('load', None, None)))
        file.chmod(0o666)
        with self.assertRaises(c.Refused): self.control.firewall_action('load')

    def test_post_copy_check_rejects_substitution_before_interpretation(self):
        self.control.reserve(self.expected)
        source = self.root / 'operation/node/control.py'; source.parent.mkdir(parents=True)
        source.write_text('inert sealed source')
        target = self.control.path(c.HELPERS + '/control.py'); target.parent.mkdir(parents=True)
        shutil.copyfile(source, target)
        (source.parent / 'near_validator.py').write_text('# inert sibling')
        shutil.copyfile(source.parent / 'near_validator.py', target.parent / 'near_validator.py')
        with patch.object(c, '__file__', str(source)):
            self.control.publication(self.expected)
            target.write_text('raise RuntimeError("must never execute")')
            with self.assertRaisesRegex(c.Refused, 'differs from the sealed'): self.control.publication(self.expected)

if __name__ == '__main__': unittest.main()

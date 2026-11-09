#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert platform/NSS boundaries with real interrupted state/data directories."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import native_host as host
import native_files as files
import native_state as lifecycle
import native_source_floor as floor
from mounts import owner
ALLOCATED_DATA = host.allocated_data


class Platform(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup); self.addCleanup(patch.stopall)
        self.root = Path(temporary.name); self.release = self.root / 'os-release'; self.cpu = self.root / 'cpuinfo'
        self.release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
        self.cpu.write_text('flags\t: avx2 sha_ni sse2\n' * 32)
        patch.object(host, 'OS_RELEASE', self.release).start(); patch.object(host, 'CPUINFO', self.cpu).start()
        patch.object(host, 'root_directory').start()
        patch.object(host, 'read', lambda p, n: files.read(p, n, os.getuid())).start()
        patch.object(host.platform, 'system', return_value='Linux').start()
        patch.object(host.platform, 'machine', return_value='x86_64').start()
        patch.object(host.os, 'cpu_count', return_value=32).start()
        patch.object(host.os, 'sysconf', side_effect=lambda key: 4096 if key == 'SC_PAGE_SIZE' else 500 * 1024**3 // 4096).start()
        self.run = lambda _args: 'systemd 255 (255.4-1ubuntu8)\n+ACL\n'

    def test_qualified_host_accepts_kernel_reserved_memory_on_nominal_512_gib(self):
        self.assertEqual(host.platform_facts('rpc', 'mainnet', self.run)['memory_bytes'], 500 * 1024**3)
        self.assertEqual(host.platform_facts('validator', 'mainnet', self.run)['systemd'], 255)

    def test_unknown_os_systemd_or_cpu_features_never_qualify(self):
        with self.assertRaises(ValueError): host.platform_facts('rpc', 'mainnet', lambda _: 'systemd 256\n')
        self.release.write_text('ID=ubuntu\nVERSION_ID="26.04"\n')
        with self.assertRaises(ValueError): host.platform_facts('rpc', 'mainnet', self.run)
        self.release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
        self.cpu.write_text('flags\t: avx2 sse2\n' * 32)
        with self.assertRaises(ValueError): host.platform_facts('rpc', 'mainnet', self.run)
        self.cpu.write_text('flags\t: avx2 sha_ni sse2\n' * 8)
        with self.assertRaises(ValueError): host.platform_facts('rpc', 'mainnet', self.run)

    def test_insufficient_capacity_and_wrong_role_refuse(self):
        with patch.object(host.os, 'cpu_count', return_value=8):
            with self.assertRaises(ValueError): host.platform_facts('validator', 'mainnet', self.run)
            with self.assertRaises(ValueError): host.platform_facts('validator', 'testnet', self.run)
        with patch.object(host.os, 'sysconf', side_effect=lambda key: 4096 if key == 'SC_PAGE_SIZE' else 256 * 1024**3 // 4096):
            with self.assertRaises(ValueError): host.platform_facts('rpc', 'mainnet', self.run)
        with self.assertRaises(ValueError): host.platform_facts('unknown', 'mainnet', self.run)
        with self.assertRaises(ValueError): host.platform_facts('validator', 'devnet', self.run)

    def with_memory(self, gib):
        return patch.object(host.os, 'sysconf', side_effect=lambda key: 4096 if key == 'SC_PAGE_SIZE' else gib * 1024**3 // 4096)

    def test_only_a_testnet_validator_runs_on_a_128_gib_machine(self):
        with self.with_memory(125):
            self.assertEqual(host.platform_facts('validator', 'testnet', self.run)['memory_bytes'], 125 * 1024**3)
            with self.assertRaises(ValueError): host.platform_facts('validator', 'mainnet', self.run)
            with self.assertRaises(ValueError): host.platform_facts('rpc', 'testnet', self.run)
        with self.with_memory(120):
            self.assertEqual(host.platform_facts('validator', 'testnet', self.run)['memory_bytes'], 120 * 1024**3)
        with self.with_memory(119):
            with self.assertRaises(ValueError): host.platform_facts('validator', 'testnet', self.run)
        with self.with_memory(299):
            with self.assertRaises(ValueError): host.platform_facts('validator', 'mainnet', self.run)
        with self.with_memory(300):
            self.assertEqual(host.platform_facts('validator', 'mainnet', self.run)['memory_bytes'], 300 * 1024**3)


class Preparation(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup); self.addCleanup(patch.stopall)
        self.root = Path(temporary.name)
        self.home = self.root / 'home'; self.state = self.home / 'state'
        self.mounts = {name: self.root / name for name in ('accounts', 'ledger', 'snapshots')}
        for path in self.mounts.values(): path.mkdir()
        for name, value in [('HOME', self.home), ('STATE', self.state), ('MOUNTS', self.mounts), ('CONFIG_ROOT', self.root / 'config')]:
            patch.object(host, name, value).start()
        patch.object(floor.units, 'MOUNTS', self.mounts).start()
        patch.object(floor, 'sync_file', lambda path: files.sync_file(path, os.getuid())).start()
        patch.object(host, 'platform_facts', return_value={'systemd': 255}).start()
        self.inspect = patch.object(host.mounts, 'inspect', return_value={}).start()
        patch.object(host, 'allocated_data', return_value=dict.fromkeys(self.mounts, 0)).start()
        self.quiet = patch.object(host.process, 'assert_quiescent').start()
        patch.object(host.tuning, 'configure', return_value={'configured': True}).start()
        patch.object(host.pwd, 'getpwnam', side_effect=KeyError).start()
        self.contract = owner(); self.plan = {'node': {'uid': os.getuid(), 'gid': os.getgid()}}
        self.provisioned = []
        def account(state, contract):
            state.owner(contract); self.provisioned.append(contract)
            state.put('accounts.json', {'contract': contract, 'accounts': self.plan, 'opening_protocol': 1})
            return self.plan
        patch.object(host.accounts, 'ensure', account).start()
        patch.object(host.accounts, 'SPECS', {'node': ('erpc-solana', str(self.home)),
            'builder': ('erpc-solana-build', str(self.root / 'builder')),
            'proof': ('erpc-solana-proof', str(self.root / 'proof'))}).start()
        def directory(path, create=False, mode=0o755):
            self.assertFalse(path.is_symlink())
            if create: path.mkdir(mode=mode, parents=True, exist_ok=True)
        patch.object(host, 'root_directory', directory).start()
        patch.object(host, 'sync_file', lambda path: files.sync_file(path, os.getuid())).start()
        patch.object(lifecycle, 'read', lambda path, maximum: files.read(path, maximum, os.getuid())).start()
        self.calls = []
        def command(argv, **_kwargs): self.calls.append(argv); return 'not-found\n'
        self.command = command

    def test_fresh_owner_and_data_are_preserved_on_init_retry(self):
        self.assertTrue(host.prepare(self.contract, self.command)['prepared'])
        payload = self.mounts['ledger'] / 'data/retained-block'; payload.write_text('inert native database')
        self.assertTrue(host.prepare(self.contract, self.command)['prepared'])
        self.assertEqual(payload.read_text(), 'inert native database')
        self.assertEqual(self.inspect.call_args.kwargs, {})
        self.assertTrue((self.state / 'data.json').exists())
        self.assertFalse(any('mount' in argv or 'mkfs' in argv for argv in self.calls))

    def test_legacy_identity_existing_units_other_profiles_and_volume_data_refuse_before_reservation(self):
        with patch.object(host.pwd, 'getpwnam', return_value=object()):
            with self.assertRaises(ValueError): host.prepare(self.contract, self.command)
        with self.assertRaises(ValueError): host.prepare(self.contract, lambda *a, **k: 'loaded\n')
        host.CONFIG_ROOT.mkdir(); (host.CONFIG_ROOT / 'another-chain').mkdir()
        with self.assertRaises(ValueError): host.prepare(self.contract, self.command)
        (host.CONFIG_ROOT / 'another-chain').rmdir(); host.CONFIG_ROOT.rmdir()
        unowned = self.mounts['accounts'] / 'unowned-data'; unowned.write_text('retain me')
        with self.assertRaises(ValueError): host.prepare(self.contract, self.command)
        self.assertEqual(unowned.read_text(), 'retain me'); self.assertFalse(self.state.exists())
        self.assertEqual(self.provisioned, [])

    def test_empty_initial_state_directory_can_retry_but_unowned_receipts_cannot_be_adopted(self):
        self.state.mkdir(parents=True, mode=0o700)
        unknown = self.state / 'unknown'; unknown.write_text('retain me')
        with self.assertRaises(ValueError): host.prepare(self.contract, self.command)
        self.assertEqual(self.provisioned, []); unknown.unlink()
        host.prepare(self.contract, self.command)

    def test_visible_data_intent_requires_durability_before_creating_payload_directories(self):
        self.state.mkdir(parents=True, mode=0o700); state = lifecycle.State(self.state); state.reserve(self.contract)
        original = state.put
        def failed(name, value):
            original(name, value)
            if name == 'data-intent.json': raise OSError('inert ambiguous intent durability')
        with patch.object(state, 'put', failed):
            with self.assertRaises(OSError): host.data_directories(state, self.contract, self.plan)
        with patch.object(host, 'sync_file', side_effect=OSError('inert persistent fsync failure')):
            with self.assertRaises(OSError): host.data_directories(state, self.contract, self.plan)
        self.assertFalse(any((path / 'data').exists() for path in self.mounts.values()))
        host.data_directories(state, self.contract, self.plan)
        self.assertTrue(all((path / 'data').is_dir() for path in self.mounts.values()))

    def test_unreceipted_data_and_changed_original_contract_never_get_adopted(self):
        self.state.mkdir(parents=True, mode=0o700); state = lifecycle.State(self.state); state.reserve(self.contract)
        path = self.mounts['ledger'] / 'data'; path.mkdir(mode=0o700)
        with self.assertRaises(ValueError): host.data_directories(state, self.contract, self.plan)
        self.assertFalse((self.state / 'data-intent.json').exists())
        path.rmdir(); host.data_directories(state, self.contract, self.plan)
        with self.assertRaises(ValueError): host.prepare(dict(self.contract, name='foreign'), self.command)

    def test_owner_only_or_empty_prepared_retry_still_requires_initial_space(self):
        # Real durable reservation/data paths; device sizes and du are inert.
        self.inspect.return_value = {kind: {'free_bytes': 1_800_000_000_000} for kind in self.mounts}
        with patch.object(host.accounts, 'ensure', side_effect=OSError('inert first account failure')):
            with self.assertRaises(OSError): host.prepare(self.contract, self.command)
        self.assertTrue((self.state / 'owner.json').exists()); self.assertFalse((self.state / 'data.json').exists())
        self.inspect.return_value = {kind: {'free_bytes': 100_000_000_000} for kind in self.mounts}
        with self.assertRaisesRegex(ValueError, 'initial synchronization'): host.prepare(self.contract, self.command)
        self.inspect.return_value = {kind: {'free_bytes': 1_800_000_000_000} for kind in self.mounts}
        host.prepare(self.contract, self.command)
        self.inspect.return_value = {kind: {'free_bytes': 100_000_000_000} for kind in self.mounts}
        with patch.object(host, 'allocated_data', ALLOCATED_DATA), patch.object(host.accounts, 'verify', return_value=self.plan):
            with self.assertRaisesRegex(ValueError, 'initial synchronization'): host.prepare(self.contract, self.command)
            self.assertFalse(any('/usr/bin/du' in call for call in self.calls))
            for mount in self.mounts.values(): (mount / 'data/retained-block').write_bytes(b'inert existing payload')
            def measure(args, **_kwargs):
                self.assertEqual(args[:5], ['/usr/bin/du', '--one-file-system', '--summarize', '--block-size=1', '--'])
                return '900000000000\t' + args[-1] + '\n'
            self.assertTrue(host.prepare(self.contract, measure)['prepared'])
            for mount in self.mounts.values():
                self.assertEqual((mount / 'data/retained-block').read_bytes(), b'inert existing payload')

    def test_unknown_inaccessible_home_is_not_silently_repaired(self):
        self.home.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, 'traversable'): host.prepare(self.contract, self.command)
        self.assertEqual(self.home.stat().st_mode & 0o777, 0o700)

    def test_each_partial_ownership_reservation_resumes_through_normal_prepare(self):
        stages = ('owner-uninitialized', 'halt.json', 'intent-fence.json', 'owner-initialized')
        for failure in stages:
            fixture = Preparation(); fixture.setUp()
            try:
                original = lifecycle.State.put
                def interrupted(state, name, value):
                    original(state, name, value)
                    selected = ('owner-initialized' if value.get('initialized') else 'owner-uninitialized') if name == 'owner.json' else name
                    if selected == failure: raise OSError('inert completed write with ambiguous return')
                with patch.object(lifecycle.State, 'put', interrupted):
                    with self.assertRaises(OSError): host.prepare(fixture.contract, fixture.command)
                self.assertFalse((fixture.state / 'data.json').exists())
                self.assertEqual(fixture.provisioned, [])
                saved = lifecycle.State(fixture.state).get('owner.json')['initial_halt']
                self.assertTrue(host.prepare(fixture.contract, fixture.command)['prepared'])
                self.assertEqual(lifecycle.State(fixture.state).get('halt.json')['generation'], saved)
                self.assertTrue((fixture.state / 'data.json').exists())
            finally: fixture.doCleanups()

    def test_partial_owner_does_not_adopt_unknown_extra_state_or_bypass_capacity(self):
        self.home.mkdir(mode=0o755); self.state.mkdir(mode=0o700)
        state = lifecycle.State(self.state)
        state.put('owner.json', {'contract': self.contract, 'initial_halt': 'e'*32, 'initialized': False})
        unknown = self.state / 'unowned'; unknown.write_text('retain')
        with self.assertRaisesRegex(ValueError, 'unexpected state'): host.prepare(self.contract, self.command)
        self.assertEqual(unknown.read_text(), 'retain'); self.assertEqual(self.provisioned, [])
        unknown.unlink()
        self.inspect.return_value = {kind: {'free_bytes': 100_000_000_000} for kind in self.mounts}
        with self.assertRaisesRegex(ValueError, 'initial synchronization'): host.prepare(self.contract, self.command)
        self.assertEqual(self.provisioned, []); self.assertFalse((self.state / 'data.json').exists())


if __name__ == '__main__': unittest.main()

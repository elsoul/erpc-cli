# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original data policy reaches actual native argv; no node/key execution."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'templates/node'))
import native_migration_settings as settings
import native_migration_inspect as legacy
import native_runtime_unit as unit
import native_files as files
from mounts import owner
try:
    from ansible.parsing.dataloader import DataLoader
    from ansible.template import Templar
except ImportError:
    Templar = None

PUBLIC = 'stNPhGRZhn4ZdKEjLAqCGBQas7XC7xeXj8ifxejsSLV'
OVERRIDE = ('staked_map_id:\n  ' + PUBLIC + ': 500000000000000\n').encode()


def startup(options=None):
    return {'mode': 'rpc', 'options': {} if options is None else options, 'overrides': None}


class Policy(unittest.TestCase):
    def test_exact_retention_unit_and_other_data_semantics_reach_native_argv(self):
        contract = owner(); catalog = json.loads((ROOT / 'templates/node/catalog.json').read_bytes())
        for flag in ('--limit-ledger-size', '--limit-blockstore-size'):
            value = settings.settings(startup({flag: ['400000000'], '--wal-recovery-mode': ['skip_any_corrupted_record'],
                '--use-snapshot-archives-at-startup': ['never'], '--no-skip-initial-accounts-db-clean': [True]}))
            argv = unit.arguments(contract, catalog, 'a'*32, 'sync', '7'*44, value)
            self.assertEqual(argv[argv.index(flag)+1], '400000000')
            self.assertNotIn((set(settings.NUMERIC[:2])-{flag}).pop(), argv)
            self.assertEqual(argv[argv.index('--use-snapshot-archives-at-startup')+1], 'never')
            self.assertIn('--no-skip-initial-accounts-db-clean', argv)
        argv = unit.arguments(contract, catalog, 'a'*32, 'sync', '7'*44, settings.settings(startup()))
        self.assertNotIn('--limit-blockstore-size', argv)
        self.assertIn('--limit-blockstore-size', unit.arguments(contract, catalog, 'a'*32, 'sync', '7'*44))

    def test_leader_safety_difference_is_public_and_bypass_never_reintroduced(self):
        value = settings.settings(startup({'--no-wait-for-vote-to-start-leader': [True]}))
        self.assertIn('rooted-vote leader safety', value['changes'][-1])
        self.assertNotIn('--no-wait-for-vote-to-start-leader', value['arguments'])
        for mode in ('sync', 'validator'):
            source = startup({'--no-wait-for-vote-to-start-leader': [True]}); source['mode'] = mode
            with self.assertRaises(ValueError): settings.settings(source)
        for argument in ('--no-wait-for-vote-to-start-leader', '--identity', '--geyser-plugin-config'):
            changed = copy.deepcopy(value); changed['arguments'] = [argument]
            with self.assertRaises(ValueError): settings.checked(changed)

    def test_override_subset_rejects_arbitrary_yaml_duplicates_bad_pubkey_and_overflow(self):
        value = legacy.staked_overrides(OVERRIDE)
        self.assertEqual(value['sha256'], hashlib.sha256(OVERRIDE).hexdigest())
        invalid = [OVERRIDE.replace(b':\n', b':\v'), OVERRIDE.replace(b'\n', b'\r\n'), OVERRIDE + b'other: true\n', OVERRIDE + OVERRIDE.splitlines(keepends=True)[1],
                   OVERRIDE.replace(b'500000000000000', b'18446744073709551616'),
                   OVERRIDE.replace(PUBLIC.encode(), b'2'*32),
                   b'staked_map_id: !!python/object/apply:anything []\n',
                   OVERRIDE.replace(b'500000000000000', b'*alias')]
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)): legacy.staked_overrides(raw)

    @unittest.skipIf(os.name != 'posix', 'native file ownership fixture requires POSIX')
    def test_original_public_copy_is_exact_and_interrupted_publication_reuses_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / 'config'; target = directory / 'overrides.yml'
            value = settings.settings(dict(startup({'--staked-nodes-overrides': ['overrides.yml']}), overrides=legacy.staked_overrides(OVERRIDE)))
            def trusted(path, create=False, mode=0o755):
                self.assertEqual(path, directory)
                if create: path.mkdir(mode=mode, exist_ok=True)
                self.assertFalse(path.is_symlink())
            with patch.object(settings, 'DIRECTORY', directory), patch.object(settings, 'OVERRIDES', target), \
                 patch.object(settings, 'root_directory', trusted), \
                 patch.object(settings, 'read', lambda p: files.read(p, owner=os.getuid())), \
                 patch.object(settings, 'sync_file', lambda p: files.sync_file(p, os.getuid())):
                with patch.object(settings, 'sync_directory', side_effect=OSError('inert fsync interruption')):
                    with self.assertRaises(OSError): settings.publish(value)
                self.assertEqual(target.read_bytes(), OVERRIDE)
                settings.publish(value); settings.verify(value)
                target.chmod(0o644); target.write_bytes(OVERRIDE.replace(b'500000000000000', b'0')); target.chmod(0o444)
                with self.assertRaises(ValueError): settings.publish(value)

    @unittest.skipIf(Templar is None, 'requires separately pinned Ansible render runtime')
    def test_actual_managed_templates_positive_and_custom_features_remain_refused(self):
        directory = ROOT.parent / 'erpc-chain-solana/templates/jinja'
        for network, role in [('mainnet', 'rpc'), ('mainnet', 'validator'), ('testnet', 'validator')]:
            variables = {'validator_type': 'agave', 'installed_agave_version': '4.3.2' if network == 'mainnet' else '4.4.0-beta.1',
                         'vote_account': '3'*44, 'identity_account': '2'*44, 'rpc_type': 'SendTx RPC'}
            templar = Templar(loader=DataLoader(), variables=variables)
            raw = templar.template((directory / (network+'-'+role) / 'start-validator.sh.j2').read_text()).encode()
            request = {'network': network, 'role': role, 'vote_account': variables['vote_account'] if role == 'validator' else None,
                       'historical': {'uid': 1001}}
            with patch.object(legacy, 'read_public', return_value=OVERRIDE) as read:
                observed = legacy.startup(raw, request)
            if network == 'mainnet' and role == 'validator':
                read.assert_called_once_with('home/solv/overrides.yml', uid=1001, maximum=16384)
                self.assertEqual(observed['overrides']['canonical_text'], OVERRIDE.decode())
            value = settings.settings(observed); settings.checked(value)
            contract = owner(); contract['network'] = network
            catalog = json.loads((ROOT / 'templates/node/catalog.json').read_bytes())
            if role == 'rpc':
                contract.update(profile='agave-native-rpc',vote_account=None,authority_account=None)
            mode = 'rpc' if role == 'rpc' else 'sync'
            identity = contract['identity_account'] if role == 'rpc' else '7'*44
            argv = unit.arguments(contract, catalog, 'a'*32, mode, identity, value)
            self.assertNotIn('--no-wait-for-vote-to-start-leader', argv)
            if value['overrides'] is not None:
                self.assertEqual(argv[argv.index('--staked-nodes-overrides')+1], str(settings.OVERRIDES))
            self.assertIn('--limit-ledger-size' if network == 'mainnet' else '--limit-blockstore-size', value['arguments'])
            for extra in (b'--geyser-plugin-config /home/solv/geyser.json', b'--wait-for-supermajority 100', b'--staked-nodes-overrides /tmp/unknown.yml'):
                with self.assertRaises(ValueError): legacy.startup(raw+b'\n'+extra, request)


if __name__ == '__main__': unittest.main()

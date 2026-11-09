# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Read-only observation and inert consensus-custody failure injection."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode = True
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / 'templates/node'))
import control as c
c.ROOT_UID = os.getuid()  # Temporary root authority modeled by the test account.
import near_validator as v
import setup


def base58(raw):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    number, text = int.from_bytes(raw, 'big'), ''
    while number:
        number, digit = divmod(number, 58)
        text = alphabet[digit] + text
    return '1' * (len(raw) - len(raw.lstrip(b'\0'))) + text


# Public RFC8032 test vector; never a node identity or funded account.
PUBLIC = bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
SEED = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')


def expected():
    return {'owner': 'fixtureowner', 'network': 'testnet', 'role': 'validator',
            'genesis_hash': c.PINS['testnet']['genesis_hash'], 'validator_account': 'fixture.pool.f863973.m0',
            'owner_account': 'owner.testnet', 'staking_public_key': 'ed25519:' + base58(PUBLIC),
            'commission_basis_points': 500}


class Observer(unittest.TestCase):
    def setUp(self):
        self.expected = expected()
        self.pool = True
        self.block = 'A' * 44
        self.overrides = {}
        self.calls = []

    def query(self, network, method, params):
        self.calls.append((network, method, params))
        if method == 'status':
            return self.overrides.get('status', {'chain_id': network, 'genesis_hash': self.expected['genesis_hash'],
                'sync_info': {'syncing': False, 'latest_block_time': 'fixture', 'latest_block_hash': self.block, 'latest_block_height': 123}})
        if method == 'block':
            self.assertEqual(params, {'block_id': self.block})
            return {'header': {'hash': self.block, 'height': 123, 'epoch_id': 'B' * 44}}
        if method == 'validators':
            self.assertEqual(params, {'epoch_id': 'B' * 44})
            return self.overrides.get('validators', {'current_validators': [], 'next_validators': [], 'current_proposals': []})
        self.assertEqual(method, 'query')
        self.assertEqual(params['block_id'], self.block)
        who, kind = params['account_id'], params['request_type']
        if kind == 'view_account':
            if who == v.FACTORIES[network]:
                result = {'code_hash': self.overrides.get('factory_code', v.FACTORY_CODE)}
            elif not self.pool: return None
            else: result = {'code_hash': self.overrides.get('pool_code', v.POOL_CODE)}
        elif kind == 'view_access_key_list':
            key = 'owner_keys' if who == self.expected['owner_account'] else 'pool_keys'
            result = {'keys': self.overrides.get(key, [{'public_key': 'external-owner-public-fixture'}] if key == 'owner_keys' else [])}
        else:
            values = {'get_min_attached_balance': '30000000000000000000000000',
                      'get_owner_id': self.expected['owner_account'], 'get_staking_key': self.expected['staking_public_key'],
                      'get_reward_fee_fraction': {'numerator': 5, 'denominator': 100}, 'is_staking_paused': False,
                      'get_account_staked_balance': '100', 'get_account_unstaked_balance': '50',
                      'is_account_unstaked_balance_available': False}
            name = params['method_name']
            result = {'result': list(json.dumps(self.overrides.get(name, values[name])).encode())}
        result['block_hash'] = self.overrides.get('result_block', self.block)
        return result

    def observe(self): return v.observe(self.expected, lambda _: 1, self.query)

    def test_public_observations_are_bound_to_one_block_and_never_submit(self):
        result = self.observe()
        self.assertTrue(result['pool_exists'])
        self.assertFalse(result['current_validators'])
        self.assertEqual(result['minimum_deposit_yocto'], '30000000000000000000000000')
        self.assertEqual({method for _, method, _ in self.calls}, {'status', 'block', 'query', 'validators'})
        self.pool = False
        self.assertFalse(self.observe()['pool_exists'])

    def test_wrong_code_owner_key_fee_or_access_authority_is_refused(self):
        for key, value in [('factory_code', 'other'), ('pool_code', 'other'),
                           ('get_owner_id', 'different.testnet'), ('get_staking_key', 'other'),
                           ('get_reward_fee_fraction', {'numerator': 1, 'denominator': 10}),
                           ('get_reward_fee_fraction', {'numerator': 0, 'denominator': 0}),
                           ('is_staking_paused', 'false'), ('get_min_attached_balance', '0'),
                           ('get_min_attached_balance', '1e24'), ('result_block', 'B' * 44),
                           ('owner_keys', []), ('pool_keys', [{'public_key': 'unexpected'}]),
                           ('owner_keys', [{'public_key': self.expected['staking_public_key']}])]:
            with self.subTest(key=key, value=value):
                self.overrides = {key: value}
                with self.assertRaises(ValueError): self.observe()

    def test_membership_never_confuses_different_keys_or_accounts(self):
        for field in ('current_validators', 'next_validators', 'current_proposals'):
            entry = {'account_id': self.expected['validator_account'], 'public_key': self.expected['staking_public_key']}
            table = {name: [] for name in ('current_validators', 'next_validators', 'current_proposals')}
            table[field] = [entry]
            self.overrides = {'validators': table}
            self.assertTrue(self.observe()[field])
            for delta in ({'account_id': 'other.testnet'}, {'public_key': 'another-key'}):
                table[field] = [dict(entry, **delta)]
                with self.assertRaises(ValueError): self.observe()
            table[field] = [entry, entry]
            with self.assertRaises(ValueError): self.observe()

    def test_wrong_network_or_stale_observer_is_not_an_absent_pool(self):
        for mutate in ('chain_id', 'genesis_hash'):
            value = self.query('testnet', 'status', [])
            value[mutate] = 'wrong'
            self.overrides = {'status': value}
            with self.assertRaises(ValueError): self.observe()
            self.overrides = {}
        with self.assertRaises(ValueError): v.observe(self.expected, lambda _: 301, self.query)

    def test_transport_refuses_write_methods_before_network_access(self):
        with patch('urllib.request.build_opener', side_effect=AssertionError('no connection')):
            for method in ('broadcast_tx_commit', 'send_tx', 'EXPERIMENTAL_tx_status'):
                with self.assertRaises(ValueError): v.request('testnet', method, {})
            with self.assertRaises(ValueError): v.request('testnet', 'query', {'request_type': 'write'})

    def test_optional_owner_balance_observation_uses_explicit_owner_and_exact_amounts(self):
        result = v.observe(self.expected, lambda _: 1, self.query, balances=True)
        self.assertEqual(result['owner_balance'], {'staked_yocto': '100', 'unstaked_yocto': '50', 'withdrawal_available': False})
        for _, method, params in self.calls:
            if method == 'query' and params.get('method_name', '').startswith(('get_account_', 'is_account_')):
                import base64
                self.assertEqual(json.loads(base64.b64decode(params['args_base64'])), {'account_id': self.expected['owner_account']})
        self.overrides['get_account_staked_balance'] = 100.5
        with self.assertRaises(ValueError): v.observe(self.expected, lambda _: 1, self.query, balances=True)


class Custody(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.expected = expected()
        self.calls = []
        self.sequence = 0
        def run(argv, **kwargs):
            self.calls.append(argv)
            result = b''
            if argv[:2] == ['/usr/bin/openssl', 'pkey']:
                result = bytes.fromhex('302a300506032b6570032100') + PUBLIC
            if argv[:2] == ['systemd-creds', 'encrypt']:
                self.sequence += 1
                Path(argv[-1]).write_bytes(b'inert encrypted bytes ' + str(self.sequence).encode())
            return subprocess.CompletedProcess(argv, 0, result, b'')
        self.control = c.Control(self.root, run=run)
        self.control.path('/opt/erpc').mkdir(parents=True)
        self.control.reserve(self.expected)
        self.raw = json.dumps({'account_id': self.expected['validator_account'], 'public_key': self.expected['staking_public_key'],
                               'secret_key': 'ed25519:' + base58(SEED + PUBLIC)})
        self.request = {'key_file': self.raw, 'keys_unhosted': True, 'restore': False, 'intent': 'a' * 32, 'policy_sha256': 'b' * 64}
        self.addCleanup(patch.stopall)
        # NSS/home authority is exercised by accounts.py; custody fixtures use
        # the verified original numeric identity without mutating real accounts.
        self.account = patch.object(self.control, 'account', return_value=(1234, 1234)).start()
        self.prepared = patch.object(self.control, 'prepared').start()
        self.stopped = patch.object(self.control, 'stopped').start()
        self.observed = {'current_validators': False, 'next_validators': False}
        patch.object(v, 'observe', side_effect=lambda *_: self.observed).start()

    def do_import(self, **kwargs):
        return v.import_key(self.control, self.expected, dict(self.request, **kwargs), c.block_age)

    def test_account_drift_refuses_import_and_runtime_material_before_key_tools(self):
        with patch.object(self.control, 'account', side_effect=c.Refused('inert original NSS drift')), \
             patch.object(v, 'key_material') as material, patch.object(self.control, 'identity') as peer:
            with self.assertRaises(c.Refused): self.do_import()
            with self.assertRaises(c.Refused): self.control.stage_runtime_key(self.expected)
            material.assert_not_called(); peer.assert_not_called()
        self.assertEqual(self.calls, [])
        self.assertFalse((self.control.directory / 'validator-identity.json').exists())

    def test_native_secret_pair_is_checked_without_private_argv(self):
        self.do_import()
        self.assertNotIn(base58(SEED + PUBLIC), json.dumps(self.calls))
        receipt = v.identity(self.control, self.expected)
        self.assertEqual(receipt['plaintext_sha256'], self.control.digest(self.raw.encode()))
        self.assertFalse((self.control.directory / 'validator-import.json').exists())
        with self.assertRaises(ValueError):
            v.key_material(self.control, self.expected, self.raw.replace(base58(SEED + PUBLIC), base58(SEED + bytes(32))).encode())
        duplicate = self.raw[:-1] + ',"account_id":"other.testnet"}'
        with self.assertRaises(ValueError): v.key_material(self.control, self.expected, duplicate.encode())

    def test_first_import_requires_fresh_assertion_and_never_adopts_active_or_orphan_material(self):
        with self.assertRaises(ValueError): self.do_import(keys_unhosted=False)
        for field in ('current_validators', 'next_validators'):
            self.observed[field] = True
            with self.assertRaises(ValueError): self.do_import()
            self.observed[field] = False
        orphan = self.control.path('/etc/credstore.encrypted/near-validator.key')
        orphan.parent.mkdir(parents=True)
        orphan.write_bytes(b'orphan'); orphan.chmod(0o600)
        with self.assertRaises(ValueError): self.do_import()
        self.assertEqual(orphan.read_bytes(), b'orphan')

    def test_original_restore_fences_before_fallible_stop_and_retains_cipher_generations(self):
        self.do_import()
        self.stopped.side_effect = c.Refused('shutdown failure')
        with self.assertRaises(c.Refused): self.do_import(restore=True)
        for marker in ('stopped', 'activation-revoked'):
            self.assertTrue((self.control.directory / marker).exists())
        self.assertEqual(self.control.read('operation.json'), {'intent': None})
        self.stopped.side_effect = None
        self.do_import(restore=True)
        self.assertTrue(list(self.control.path('/etc/credstore.encrypted').glob('near-validator.previous.*')))
        with self.assertRaises(ValueError): self.do_import(restore=True, key_file=self.raw + ' ')

    def test_failed_restore_publication_retains_independent_cipher_inodes_and_can_resume(self):
        self.do_import()
        encrypted = self.control.path('/etc/credstore.encrypted/near-validator.key')
        original = encrypted.read_bytes()
        real_replace = v.os.replace
        def fail(source, destination):
            if Path(destination) == encrypted: raise OSError('inert interruption after retention')
            return real_replace(source, destination)
        with patch.object(v.os, 'replace', side_effect=fail):
            with self.assertRaises(OSError): self.do_import(restore=True)
        previous = list(encrypted.parent.glob('near-validator.previous.*'))
        self.assertEqual(len(previous), 1)
        self.assertEqual(previous[0].read_bytes(), original)
        self.assertEqual(encrypted.read_bytes(), original)
        self.assertEqual(encrypted.stat().st_nlink, 1)
        self.assertNotEqual(encrypted.stat().st_ino, previous[0].stat().st_ino)
        self.control.contract(self.expected)
        self.do_import(keys_unhosted=False)
        v.identity(self.control, self.expected)
        self.assertEqual(previous[0].read_bytes(), original)

    def test_validator_credential_namespace_rejects_links_and_public_material(self):
        self.do_import()
        encrypted = self.control.path('/etc/credstore.encrypted/near-validator.key')
        encrypted.chmod(0o644)
        with self.assertRaises(c.Refused): self.do_import(restore=True)
        encrypted.chmod(0o600)
        alias = encrypted.with_name('near-validator.previous.' + 'a' * 64)
        os.link(encrypted, alias)
        with self.assertRaises(c.Refused): self.do_import(restore=True)
        alias.unlink(); alias.symlink_to(encrypted)
        with self.assertRaises(c.Refused): self.do_import(restore=True)
        self.assertEqual(self.sequence, 1)

    def test_receipted_interrupted_publication_resumes_only_original_bytes(self):
        real_replace = v.os.replace
        def fail(source, destination):
            if str(destination).endswith('/near-validator.key'): raise OSError('interrupted publication')
            return real_replace(source, destination)
        with patch.object(v.os, 'replace', side_effect=fail):
            with self.assertRaises(OSError): self.do_import()
        receipt = self.control.read('validator-identity.json')
        pending = self.control.path('/etc/credstore.encrypted') / receipt['pending_file']
        self.assertTrue(pending.exists())
        self.do_import(keys_unhosted=False)
        self.assertFalse(pending.exists())
        self.assertFalse((self.control.directory / 'validator-import.json').exists())
        v.identity(self.control, self.expected)

    def test_existing_cipher_corruption_never_generates_a_new_identity_implicitly(self):
        self.do_import()
        encrypted = self.control.path('/etc/credstore.encrypted/near-validator.key')
        encrypted.write_bytes(b'changed')
        with self.assertRaises(ValueError): self.do_import()
        self.assertEqual(self.sequence, 1)
        self.do_import(restore=True)
        self.assertEqual(self.sequence, 2)

    def test_failed_encryption_resumes_same_intent_without_publishing_authority(self):
        original = self.control.command
        def fail(*argv, **kwargs):
            if argv[:2] == ('systemd-creds', 'encrypt'): raise c.Refused('encryption failure')
            return original(*argv, **kwargs)
        with patch.object(self.control, 'command', side_effect=fail):
            with self.assertRaises(c.Refused): self.do_import()
        self.assertFalse((self.control.directory / 'validator-identity.json').exists())
        self.do_import()
        v.identity(self.control, self.expected)

    def test_configuration_and_contract_cannot_swap_roles_or_expose_validator_rpc(self):
        bad = dict(self.expected, role='rpc')
        with self.assertRaises(c.Refused): self.control.contract(bad)
        peers = ['ed25519:' + base58(PUBLIC) + '@8.8.8.8:24567']
        base = {'rpc': {}, 'network': {}}
        configured = setup.configuration(base, self.expected, False, False, peers)
        self.assertEqual(configured['validator_key_file'], '/run/near-keys/validator_key.json')
        self.assertEqual(configured['rpc']['addr'], '127.0.0.1:3030')
        with self.assertRaises(c.Refused): setup.configuration(base, self.expected, True, False, peers)

    def peer(self):
        raw = json.dumps({'account_id': 'node', 'public_key': self.expected['staking_public_key'], 'secret_key': 'inert-peer-fixture'}).encode()
        encrypted = self.control.path('/etc/credstore.encrypted/near-node.key')
        encrypted.parent.mkdir(parents=True, exist_ok=True)
        encrypted.write_bytes(b'inert peer cipher'); encrypted.chmod(0o600)
        self.control.write('identity.json', {'contract': self.expected, 'cipher_sha256': self.control.file_digest(encrypted),
                                           'plaintext_sha256': self.control.digest(raw), 'public_key': self.expected['staking_public_key']})
        return raw

    def test_runtime_keys_use_root_owned_atomic_files_without_following_node_links(self):
        self.do_import()
        peer = self.peer()
        credentials = self.control.path('/run/credentials/near-node.service')
        credentials.mkdir(parents=True)
        (credentials / 'node-key.json').write_bytes(peer)
        (credentials / 'validator-key.json').write_text(self.raw)
        keys = self.control.path('/run/erpc-near/keys')
        keys.mkdir(parents=True)
        outside = self.root / 'outside'
        outside.write_bytes(b'unchanged database fixture')
        (keys / 'node_key.json').symlink_to(outside)
        # Another file shape that O_TRUNC would corrupt even with O_NOFOLLOW.
        import os
        os.link(outside, keys / 'validator_key.json')
        with patch.object(c.os, 'chown') as chown:
            self.assertEqual(self.control.stage_runtime_key(self.expected), (1234, 1234))
        self.assertEqual(outside.read_bytes(), b'unchanged database fixture')
        self.assertEqual((keys / 'validator_key.json').read_text(), self.raw)
        self.assertEqual(keys.stat().st_mode & 0o777, 0o750)
        self.assertEqual((keys / 'validator_key.json').stat().st_mode & 0o777, 0o440)
        self.assertTrue(all(call.args[1:] == (0, 1234) for call in chown.call_args_list))
        (credentials / 'validator-key.json').write_text(self.raw + ' ')
        with patch.object(c.os, 'chown'):
            with self.assertRaises(c.Refused): self.control.stage_runtime_key(self.expected)

    def test_startup_requires_consensus_receipt_clock_and_fresh_registration_but_stop_does_not(self):
        self.do_import()
        self.peer()
        target = {key: c.PINS['testnet'][key] for key in ('version', 'commit', 'image')}
        config = self.control.path('/etc/near')
        config.mkdir(parents=True)
        for kind in ('config', 'genesis'):
            path = config / (kind + '.json')
            path.write_text('{}')
            target[kind + '_sha256'] = self.control.file_digest(path)
        target['policy_sha256'] = 'b' * 64
        self.control.write('installed.json', target)
        self.control.write('firewall.json', {'run': 'run-fixture', 'bundle': 'c' * 64})
        with patch.object(self.control, 'firewall'), patch.object(self.control, 'capacity'), patch.object(self.control, 'clock') as clock:
            self.control.guard(self.expected)
            clock.side_effect = c.Refused('unsynchronized clock')
            with self.assertRaises(c.Refused): self.control.guard(self.expected)
            clock.side_effect = None
            with patch.object(v, 'observe', side_effect=ValueError('wrong pool key')):
                with self.assertRaises(ValueError): self.control.guard(self.expected)
                self.control.dispatch('stop', self.expected)
            self.assertEqual(self.control.read('operation.json'), {'intent': None})
            with self.assertRaises(c.Refused): self.control.guard(self.expected)

    def test_existing_time_daemons_are_preserved(self):
        import time_service
        for daemon in ('chrony.service', 'chronyd.service', 'ntp.service', 'ntpd.service'):
            self.assertEqual(time_service.choose({daemon: {'state': 'running'}}), {'service': daemon, 'install_fallback': False})
        self.assertEqual(time_service.choose({})['service'], 'systemd-timesyncd.service')


if __name__ == '__main__': unittest.main()

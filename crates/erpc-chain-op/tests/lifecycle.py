# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Executable failure injection with inert files; never start clients or generate keys."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
sys.dont_write_bytecode = True
ROOT = Path(__file__).parents[1] / 'templates/scripts'

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

c = load('rollup_control', 'control.py')
b = load('rollup_bootstrap', 'bootstrap.py')
s = load('rollup_status', 'status.py')
container = load('rollup_container', 'container.py')
install = load('rollup_install', 'install.py')

class OwnedTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.addCleanup(patch.stopall)
        self.root = Path(folder.name)
        self.conf, self.data, self.opt, self.lib = [self.root / n for n in ('conf', 'data', 'opt', 'lib')]
        for path in [self.conf, self.data, self.opt, self.lib, self.data/'execution', self.data/'consensus', self.data/'bootstrap-cache']:
            path.mkdir()
        for name, value in [('OWNER', self.root/'owner.json'), ('OWNER_UID', os.getuid()), ('LIB', self.lib), ('LOCK', self.root), ('CREDENTIALS', self.root/'credentials')]:
            patch.object(c, name, value).start()
        patch.object(c, 'paths', return_value=(self.conf, self.data, self.opt)).start()
        patch.object(c, 'validate_accounts', return_value=None).start()
        # This lifecycle harness already models root ownership with OWNER_UID.
        # Actual import ancestry/startup rejection is exercised in erpc-ops/tests/python_isolation.py.
        patch.object(c, 'trusted_imports', side_effect=lambda directory: self.assertEqual(directory, self.lib)).start()
        self.contract = {'owner':'syntheticowner', 'family':'optimism', 'network':'sepolia', 'history':'full'}
        self.pin = {'kind':'genesis', 'url':'', 'sha256':'', 'required_free_bytes':1_000_000_000_000, 'chain_id':11155420}
        self.pair = {'architecture':'amd64', 'execution':{'version':'2.6.1'}, 'consensus':{'version':'1.19.11'}}
        self.state = {'format':1, 'contract':self.contract, 'phase':'installed', 'bootstrap_done':True,
                      'upstreams_installed':True, 'bootstrap':self.pin, 'pair':self.pair, 'deploy_intent':'r-fixture-intent'}
        c.CREDENTIALS.mkdir()
        self.state['identity'] = {}
        for index, name in enumerate(c.IDENTITY_NAMES, 1):
            # Inert deterministic payloads and fake ciphertext; never live keys.
            plaintext = format(index, '064x').encode()
            ciphertext = ('inert encrypted ' + name).encode()
            self.state['identity'][name] = {'encrypted':c.base64.b64encode(ciphertext).decode(),
                'plaintext_sha256':hashlib.sha256(plaintext).hexdigest(),
                'cipher_sha256':hashlib.sha256(ciphertext).hexdigest()}
            (c.CREDENTIALS/c.credential_name(self.contract, name)).write_bytes(ciphertext)
        self.free = 2_000_000_000_000
        patch.object(c.shutil, 'disk_usage', side_effect=lambda _: types.SimpleNamespace(free=self.free)).start()
        self.calls = []
        self.active = {unit:'active' for unit in c.units(self.contract).values()}
        def run(argv, **kwargs):
            self.calls.append((argv, kwargs))
            if argv[:2] == ['du', '-sx']: return b'0 owned-database'
            if argv[:2] == ['systemctl', 'stop']: self.active[argv[2]] = 'inactive'
            if 'MainPID' in argv: return b'0'
            if 'LoadState' in argv: return b'loaded'
            if argv[0] == 'docker': return b'[]'
            return b''
        patch.object(c, 'run', side_effect=run).start()
        patch.object(c, 'service_active', side_effect=lambda name:self.active.get(name, 'inactive')).start()
        file = self.conf/'owned-config'; file.write_bytes(b'public protected fixture')
        (self.conf/'installation.json').write_text(json.dumps({'contract':self.contract, 'pair':self.pair,
            'files':{str(file):hashlib.sha256(file.read_bytes()).hexdigest()}}))
        c.write_state(self.state)
    def request(self, action):
        return {'contract':copy.deepcopy(self.contract), 'action':action, 'pair':copy.deepcopy(self.pair), 'bootstrap':copy.deepcopy(self.pin), 'intent':'r-fixture-intent'}
    def test_every_mutator_refuses_cross_scope_before_any_host_call(self):
        before = c.OWNER.read_bytes()
        for action in ['upstreams', 'begin-install', 'finish-install', 'start', 'stop', 'restart', 'destroy', 'reset-bootstrap', 'authorize-deploy', 'check-deploy']:
            for field, wrong in [('owner','otherowner'), ('network','mainnet'), ('family','base'), ('history','archive')]:
                request = self.request(action); request['contract'][field] = wrong
                with self.assertRaises(c.Refused): c.dispatch(request)
                self.assertEqual(self.calls, [])
                self.assertEqual(c.OWNER.read_bytes(), before)
    def test_changed_configuration_and_missing_receipt_prevent_service_start(self):
        (self.conf/'owned-config').write_bytes(b'changed listener policy')
        for action in ['start', 'restart']:
            with self.assertRaises(c.Refused): c.dispatch(self.request(action))
        self.assertFalse(any(args[:2] == ['systemctl','start'] for args,_ in self.calls))
        (self.conf/'installation.json').unlink()
        with self.assertRaises(c.Refused): c.guard(c.read_state(), 'execution')
    def test_interrupted_install_fences_boot_and_preserves_old_data(self):
        database = self.data/'execution/database-fixture'; database.write_bytes(b'inert persistent data')
        request = self.request('begin-install'); request['pair']['execution']['version'] = '2.6.2'
        c.dispatch(request)
        self.assertEqual(c.read_state()['phase'], 'installing')
        with self.assertRaises(c.Refused): c.guard(c.read_state(), 'execution')
        c.dispatch(request)
        for version in ['2.6.1','2.6.3']:
            other = copy.deepcopy(request); other['pair']['execution']['version'] = version
            with self.assertRaises(c.Refused): c.dispatch(other)
        self.assertEqual(database.read_bytes(), b'inert persistent data')
    def test_downgrade_and_insufficient_space_fail_before_stop_or_state_write(self):
        before = c.OWNER.read_bytes(); request = self.request('begin-install')
        request['pair']['execution']['version'] = '2.5.9'
        with self.assertRaises(c.Refused): c.dispatch(request)
        self.free = 1
        for action in ['begin-install','start','restart']:
            with self.assertRaises(c.Refused): c.dispatch(self.request(action))
        self.assertEqual(c.OWNER.read_bytes(), before)
        self.assertFalse(any(args[:2] == ['systemctl','stop'] for args,_ in self.calls))

    def test_reth28_forward_update_keeps_original_database_credentials_and_interrupted_target(self):
        database=self.data/'execution/original';database.write_bytes(b'inert storage-v2 original')
        original=(database.read_bytes(),database.stat().st_ino,copy.deepcopy(c.read_state()['identity']))
        request=self.request('begin-install');request['pair']['execution']['version']='2.8.0'
        with patch.object(c,'stop',side_effect=c.Refused('inert update shutdown interrupted')):
            with self.assertRaises(c.Refused):c.dispatch(request)
        self.assertEqual(c.read_state()['target'],request['pair'])
        with self.assertRaises(c.Refused):c.dispatch(self.request('begin-install'))
        c.dispatch(request)
        receipt=json.loads((self.conf/'installation.json').read_bytes());receipt['pair']=request['pair']
        (self.conf/'installation.json').write_text(json.dumps(receipt))
        with patch.object(c,'identity_material',side_effect=AssertionError('original keys must not regenerate')):
            c.dispatch(dict(request,action='finish-install'))
        self.assertEqual(c.read_state()['pair'],request['pair'])
        self.assertEqual((database.read_bytes(),database.stat().st_ino,c.read_state()['identity']),original)
        c.verify_identity(c.read_state())
        self.calls.clear()
        with self.assertRaises(c.Refused):c.dispatch(self.request('begin-install'))
        self.assertFalse(any(args[:2]==['systemctl','stop'] for args,_ in self.calls))
    def test_import_completion_cannot_waive_genesis_sync_space_or_operating_reserve(self):
        self.free = 500_000_000_000
        self.assertTrue(c.read_state()['bootstrap_done'])
        with self.assertRaises(c.Refused): c.dispatch(self.request('start'))
        with patch.object(c, 'run', return_value=b'500000000000 owned-data'):
            c.capacity(c.read_state())
            self.free = 199_999_999_999
            with self.assertRaises(c.Refused): c.capacity(c.read_state())
    def test_failed_stop_keeps_installation_fence(self):
        with patch.object(c, 'stop', side_effect=c.Refused('simulated failure')):
            with self.assertRaises(c.Refused): c.dispatch(self.request('begin-install'))
        self.assertEqual(c.read_state()['phase'], 'installing')
        with self.assertRaises(c.Refused): c.guard(c.read_state(), 'execution')
    def test_retire_preserves_database_and_prevents_boot(self):
        database = self.data/'execution/database-fixture'; database.write_bytes(b'inert persistent data')
        c.dispatch(self.request('destroy')); state = c.read_state()
        self.assertEqual(state['phase'], 'retired'); self.assertEqual(state['contract'], self.contract)
        self.assertEqual(database.read_bytes(), b'inert persistent data')
        with self.assertRaises(c.Refused): c.guard(state, 'execution')
    def test_start_bootstrap_does_not_start_execution_or_claim_readiness(self):
        state = c.read_state(); state.update(phase='bootstrapping', bootstrap_done=False); c.write_state(state)
        self.assertFalse(c.dispatch(self.request('start'))['ready'])
        self.assertIn((['systemctl', 'daemon-reload'], {}), self.calls)
        started = [args for args,_ in self.calls if args[:2] == ['systemctl','start']]
        self.assertEqual(started, [['systemctl','start','--no-block','erpc-optimism-bootstrap']])
    def test_completed_worker_recovers_crash_before_enabling_services(self):
        b.worker(copy.deepcopy(self.contract))
        self.assertTrue(any(args[:2] == ['systemctl','enable'] for args,_ in self.calls))
        self.assertTrue(any(args[:3] == ['systemctl','start','--no-block'] for args,_ in self.calls))
        self.assertEqual(c.read_state()['phase'], 'installed')
    def test_explicit_reset_quarantines_only_incomplete_bootstrap_and_recovers_interruptions(self):
        with self.assertRaises(c.Refused): c.dispatch(self.request('reset-bootstrap'))
        state = c.read_state(); state.update(phase='bootstrapping', bootstrap_done=False); c.write_state(state)
        source = self.data/'execution'/'partial'; source.write_bytes(b'incomplete data')
        peer = self.data/'consensus'/'peer-fixture'; peer.write_bytes(b'identity remains')
        account = types.SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        original_rename = c.os.rename
        def interrupted(old, new):
            original_rename(old, new)
            raise OSError('simulated power loss after atomic quarantine rename')
        with patch.object(c.pwd, 'getpwnam', return_value=account), patch.object(c.os, 'rename', side_effect=interrupted):
            with self.assertRaises(OSError): c.dispatch(self.request('reset-bootstrap'))
        self.assertEqual(c.read_state()['phase'], 'resetting')
        with self.assertRaises(c.Refused): c.dispatch(self.request('begin-install'))
        with self.assertRaises(c.Refused): c.guard(c.read_state(), 'execution')
        with patch.object(c.pwd, 'getpwnam', return_value=account):
            result = c.dispatch(self.request('reset-bootstrap'))
        self.assertFalse(result['data_deleted'])
        self.assertEqual(c.read_state()['phase'], 'prepared')
        self.assertFalse(any((self.data/'execution').iterdir()))
        self.assertEqual((Path(result['quarantine'])/'execution'/'partial').read_bytes(), b'incomplete data')
        self.assertEqual(peer.read_bytes(), b'identity remains')
        self.assertEqual(c.read_state()['pair'], self.pair)
    def test_superseded_bootstrap_cannot_publish_completion_or_start_services(self):
        state = c.read_state(); state.update(phase='bootstrapping', bootstrap_done=False); c.write_state(state)
        (self.conf/'network.json').write_text(json.dumps({'execution_chain':'optimism-sepolia'}))
        def supersede(*_):
            current = c.read_state(); current['phase'] = 'resetting'; c.write_state(current)
        with patch.object(b.fcntl, 'flock', side_effect=supersede):
            with self.assertRaises(c.Refused): b.worker(copy.deepcopy(self.contract))
        self.assertFalse(c.read_state()['bootstrap_done'])
        self.assertFalse(any(args[:2] == ['systemctl', 'start'] for args,_ in self.calls))
    def test_reset_failed_stop_never_moves_data(self):
        state = c.read_state(); state.update(phase='bootstrapping', bootstrap_done=False); c.write_state(state)
        source = self.data/'execution'/'partial'; source.write_bytes(b'partial')
        with patch.object(c, 'stop', side_effect=c.Refused('not stopped')):
            with self.assertRaises(c.Refused): c.dispatch(self.request('reset-bootstrap'))
        self.assertTrue(source.exists())
        self.assertEqual(c.read_state()['phase'], 'resetting')
    def test_bootstrap_scope_rejects_private_or_other_network_sources(self):
        for pin in [dict(self.pin, chain_id=1), dict(self.pin, kind='op-archive', url='http://127.0.0.1', sha256='a'*64),
                    dict(self.pin, required_free_bytes=True), dict(self.pin, kind='base-manifest', url='https://github.com', sha256='a'*64)]:
            with self.assertRaises(c.Refused): c.validate_bootstrap(self.contract, pin)
        c.validate_bootstrap(self.contract, self.pin)
    def test_root_owner_and_symlink_protection(self):
        with patch.object(c, 'OWNER_UID', os.getuid()+1):
            with self.assertRaises(c.Refused): c.read_state()
        original = c.OWNER.read_bytes(); c.OWNER.unlink()
        actual = self.root/'other.json'; actual.write_bytes(original); c.OWNER.symlink_to(actual)
        with self.assertRaises(c.Refused): c.read_state()
    def test_orphan_container_requires_exact_labels_and_real_daemon_response(self):
        original = {'Id':'a'*64, 'Name':'/erpc-optimism-execution', 'Config':{'Labels':{'erpc.'+k:v for k,v in self.contract.items()}}, 'State':{'Running':True}}
        with patch.object(c, 'run', side_effect=[json.dumps([original]).encode(), b'', b'[]', b'[]']) as called:
            container.stop_owned(c.read_state(), 'execution')
            self.assertIn('stop', called.call_args_list[1].args[0])
            self.assertEqual(called.call_args_list[1].args[0][-1], 'a'*64)
        replacement = copy.deepcopy(original); replacement['Id'] = 'b'*64
        with patch.object(c, 'run', side_effect=[json.dumps([original]).encode(), b'', b'[]', json.dumps([replacement]).encode()]):
            with self.assertRaises(c.Refused): container.stop_owned(c.read_state(), 'execution')
        wrong = copy.deepcopy(original); wrong['Config']['Labels']['erpc.network'] = 'mainnet'
        with patch.object(c, 'run', return_value=json.dumps([wrong]).encode()) as called:
            with self.assertRaises(c.Refused): container.stop_owned(c.read_state(), 'execution')
            self.assertEqual(called.call_count, 1)
        with patch.object(c, 'run', return_value=b''):
            with self.assertRaises(c.Refused): container.stop_owned(c.read_state(), 'execution')

    def test_established_identity_loss_corruption_and_substitution_never_regenerate(self):
        for name in c.IDENTITY_NAMES:
            file = c.CREDENTIALS/c.credential_name(self.contract, name)
            original = file.read_bytes()
            for invalid in (None, b'corrupted ciphertext', b'another valid-looking sealed identity'):
                if invalid is None: file.unlink()
                else: file.write_bytes(invalid)
                with patch.object(c, 'identity_material', side_effect=AssertionError('must not generate')):
                    for action in ('start', 'restart', 'begin-install', 'reset-bootstrap'):
                        with self.assertRaises(c.Refused): c.dispatch(self.request(action))
                    with self.assertRaises(c.Refused): c.initialize_identity(c.read_state())
                file.write_bytes(original)
        self.assertFalse(any(args[:2] == ['systemctl', 'start'] for args,_ in self.calls))
    def test_initial_identity_publication_recovers_exact_ciphertext_after_interruption(self):
        state = c.read_state(); state.pop('pair'); state.pop('identity'); state['phase']='installing'
        for file in c.CREDENTIALS.iterdir(): file.unlink()
        c.write_state(state)
        values = [format(index, '064x').encode() for index in range(1,4)]
        original_atomic = c.atomic
        published = []
        def interrupted(path, value, mode=0o600):
            if path.parent == c.CREDENTIALS:
                if published: raise OSError('power loss during credential publication')
                published.append(path)
            original_atomic(path, value, mode)
        def encrypt(argv, **kwargs):
            self.assertEqual(argv[:2], ['systemd-creds','encrypt'])
            self.assertNotIn(kwargs['data'].decode(), ' '.join(argv))
            return b'inert ciphertext for ' + argv[2].encode()
        with patch.object(c, 'identity_material', side_effect=values), patch.object(c, 'run', side_effect=encrypt), patch.object(c, 'atomic', side_effect=interrupted):
            with self.assertRaises(OSError): c.initialize_identity(state)
        persisted = c.read_state()
        self.assertIn('identity', persisted)
        self.assertEqual(len(list(c.CREDENTIALS.iterdir())), 1)
        before = copy.deepcopy(persisted['identity'])
        with patch.object(c, 'identity_material', side_effect=AssertionError('must not regenerate')), patch.object(c, 'run', side_effect=AssertionError('must not encrypt again')):
            c.initialize_identity(persisted)
        self.assertEqual(c.read_state()['identity'], before)
        c.verify_identity(persisted)
        for value in values:
            self.assertNotIn(value.decode(), c.OWNER.read_text())
    def test_stop_or_superseding_operation_revokes_every_delayed_deploy_mutator(self):
        original = copy.deepcopy(self.state)
        for cancel in ('stop', 'destroy', 'supersede'):
            c.write_state(original)
            if cancel == 'supersede':
                request = self.request('authorize-deploy'); request['intent']='r-another-intent'
                c.dispatch(request)
            else:
                c.dispatch(self.request(cancel))
            after = c.OWNER.read_bytes(); self.calls.clear()
            for action in ('check-deploy', 'upstreams', 'begin-install', 'finish-install', 'start'):
                with self.assertRaises(c.Refused): c.dispatch(self.request(action))
                self.assertEqual(c.OWNER.read_bytes(), after)
                self.assertFalse(self.calls)
        # A fresh explicit deployment is authorized independently after a stop.
        c.write_state(original); c.dispatch(self.request('stop'))
        request=self.request('authorize-deploy'); request['intent']='r-fresh-intent'
        c.dispatch(request)
        request['action']='begin-install'; c.dispatch(request)
        self.assertEqual(c.read_state()['phase'],'installing')
    def test_stopped_bootstrap_worker_cannot_complete_after_intent_is_revoked(self):
        state=c.read_state(); state.update(phase='bootstrapping', bootstrap_done=False); c.write_state(state)
        (self.conf/'network.json').write_text(json.dumps({'execution_chain':'optimism-sepolia'}))
        def canceled(*_):
            current=c.read_state(); current['deploy_intent']=None; c.write_state(current)
        with patch.object(b.fcntl,'flock',side_effect=canceled):
            with self.assertRaises(c.Refused): b.worker(copy.deepcopy(self.contract))
        self.assertFalse(c.read_state()['bootstrap_done'])
        self.assertFalse(any(args[:2]==['systemctl','start'] for args,_ in self.calls))
    def test_repeated_stop_revokes_bootstrap_even_without_a_deploy_intent(self):
        state=c.read_state(); state.update(phase='bootstrapping', bootstrap_done=False, deploy_intent=None); c.write_state(state)
        (self.conf/'network.json').write_text(json.dumps({'execution_chain':'optimism-sepolia'}))
        def canceled(*_):
            current=c.read_state(); c.cancel_deployment(current); c.write_state(current)
        with patch.object(b.fcntl,'flock',side_effect=canceled):
            with self.assertRaises(c.Refused): b.worker(copy.deepcopy(self.contract))
        self.assertFalse(c.read_state()['bootstrap_done'])
        self.assertEqual(c.read_state()['lifecycle_generation'],1)
        state=c.read_state(); state.update(phase='installed',bootstrap_done=True); c.write_state(state)
        with patch.object(b.fcntl,'flock',side_effect=canceled):
            with self.assertRaises(c.Refused): b.worker(copy.deepcopy(self.contract))
        self.assertFalse(any(args[:2]==['systemctl','start'] for args,_ in self.calls))
    def test_peer_scalar_generation_rejects_zero_and_curve_order_without_real_entropy(self):
        values = [bytes(32), c.SECP256K1_ORDER.to_bytes(32,'big'), (c.SECP256K1_ORDER-1).to_bytes(32,'big')]
        with patch.object(c.secrets,'token_bytes',side_effect=values) as generated:
            result = c.identity_material('consensus-peer')
        self.assertEqual(int(result,16),c.SECP256K1_ORDER-1)
        self.assertEqual(generated.call_count,3)
    def test_initial_crypto_failure_publishes_no_partial_identity(self):
        state = c.read_state(); state.pop('pair'); state.pop('identity'); state['phase']='installing'
        for file in c.CREDENTIALS.iterdir(): file.unlink()
        c.write_state(state)
        with patch.object(c, 'identity_material', return_value=b'a'*64), patch.object(c, 'run', side_effect=c.Refused('failed encryption')):
            with self.assertRaises(c.Refused): c.initialize_identity(state)
        self.assertNotIn('identity', c.read_state())
        self.assertFalse(any(c.CREDENTIALS.iterdir()))
    def test_runtime_plaintext_must_match_original_receipt_and_valid_scalar(self):
        runtime = self.root/'runtime'; runtime.mkdir()
        with patch.dict(os.environ, {'CREDENTIALS_DIRECTORY':str(runtime)}):
            for index, name in enumerate(c.IDENTITY_NAMES, 1):
                file = runtime/name
                original = format(index, '064x').encode(); file.write_bytes(original)
                self.assertEqual(c.runtime_identity(c.read_state(), name), original)
                for invalid in (b'b'*64, b'0'*64, b'not a peer credential'):
                    file.write_bytes(invalid)
                    with self.assertRaises(c.Refused): c.runtime_identity(c.read_state(), name)
                file.unlink()
                with self.assertRaises(c.Refused): c.runtime_identity(c.read_state(), name)
    def test_native_missing_or_inactive_unit_cannot_authorize_a_surviving_writer(self):
        self.contract['family']='base'; self.state['contract']=self.contract
        self.state['bootstrap']['kind']='base-manifest'; self.state['bootstrap']['chain_id']=84532
        self.state['bootstrap']['url']='https://sepolia-v2-snapshots.base.org/123/manifest.json'; self.state['bootstrap']['sha256']='a'*64
        self.pin=self.state['bootstrap']
        for name in c.IDENTITY_NAMES:
            previous=c.CREDENTIALS/('erpc-optimism-'+name)
            previous.rename(c.CREDENTIALS/('erpc-base-'+name))
        c.write_state(self.state)
        proc=self.root/'proc'; proc.mkdir(); process=proc/'123'; process.mkdir()
        (process/'status').write_text('Name: native-fixture\nUid:\t1234\t1234\t1234\t1234\n')
        database=self.data/'execution'/'fixture'; database.write_bytes(b'never move a live database')
        account=types.SimpleNamespace(pw_uid=1234, pw_gid=1234)
        original=c.run
        def missing(argv, **kwargs):
            if 'LoadState' in argv: return b'not-found'
            return original(argv,**kwargs)
        with patch.object(c,'PROC',proc), patch.object(c.pwd,'getpwnam',return_value=account):
            for loaded in ('missing','inactive'):
                runner=patch.object(c,'run',side_effect=missing) if loaded=='missing' else patch.object(c,'service_active',return_value='inactive')
                with runner:
                    for action in ('stop','destroy','begin-install','reset-bootstrap'):
                        state=copy.deepcopy(self.state); state['bootstrap_done']=action!='reset-bootstrap'; c.write_state(state)
                        with self.assertRaises(c.Refused): c.dispatch(self.request(action))
                        self.assertEqual(database.read_bytes(),b'never move a live database')
                        if action=='begin-install': self.assertEqual(c.read_state()['phase'],'installing')
                        if action=='reset-bootstrap': self.assertEqual(c.read_state()['phase'],'resetting')
            # A foreign-UID native executable also cannot be mistaken for quiescence.
            (process/'status').write_text('Uid:\t0\t0\t0\t0\n')
            (process/'exe').symlink_to('/opt/erpc/base/releases/qualified/base-reth-node')
            with self.assertRaises(c.Refused): c.native_quiescent(self.contract,[])
            (process/'exe').unlink()
            (process/'cmdline').write_bytes(b'python3\0'+str(c.LIB/'rollup_bootstrap.py').encode()+b'\0syntheticowner\0base\0')
            with self.assertRaises(c.Refused): c.native_quiescent(self.contract,[])
            (process/'cmdline').unlink()
            c.native_quiescent(self.contract,[])
    def test_native_cgroup_child_and_unreadable_process_ownership_fail_closed(self):
        group=self.root/'cgroup'; nested=group/'system.slice'/'erpc-base-execution.service'; nested.mkdir(parents=True)
        (nested/'cgroup.procs').write_text('777\n')
        account=types.SimpleNamespace(pw_uid=1234,pw_gid=1234)
        with patch.object(c,'CGROUP',group), patch.object(c.pwd,'getpwnam',return_value=account):
            with self.assertRaises(c.Refused): c.native_quiescent({'family':'base'},['/system.slice/erpc-base-execution.service'])
            empty=self.root/'empty-proc'; empty.mkdir()
            with patch.object(c,'PROC',empty):
                with self.assertRaises(c.Refused): c.native_quiescent({'family':'base'},[])
    def test_credential_write_needs_confirmed_receipt_and_never_persists_plaintext(self):
        shared = ROOT.parents[2] / 'erpc-chain-rollup/templates/scripts/upstreams.py'
        # Use the actual transport schema without making any provider request.
        spec = importlib.util.spec_from_file_location('rollup_upstreams', shared)
        module = importlib.util.module_from_spec(spec); sys.modules['rollup_upstreams'] = module; spec.loader.exec_module(module)
        request = self.request('upstreams')
        request['firewall'] = {'run':'r-20261026t120000-abc123', 'bundle':'a'*64}
        request['upstreams'] = {'execution':{'url':'https://github.com', 'headers':{'Authorization':'unit-test-placeholder'}}, 'beacon':{'url':'https://github.com'}}
        patch.object(c, 'CREDENTIALS', self.root/'credentials').start()
        before = c.OWNER.read_bytes()
        with patch.object(c, 'run', side_effect=c.Refused('revoked receipt')):
            with self.assertRaises(c.Refused): c.dispatch(request)
        self.assertEqual(c.OWNER.read_bytes(), before)
        self.assertFalse((c.CREDENTIALS/'erpc-optimism-l1-upstreams').exists())
        self.calls.clear()
        def invoke(argv, **kwargs):
            self.calls.append((argv, kwargs))
            return b'encrypted-fixture' if argv[0] == 'systemd-creds' else b''
        with patch.object(c, 'run', side_effect=invoke): c.dispatch(request)
        self.assertNotIn('unit-test-placeholder', c.OWNER.read_text())
        self.assertEqual((c.CREDENTIALS/'erpc-optimism-l1-upstreams').read_bytes(), b'encrypted-fixture')
        self.assertTrue(any(b'unit-test-placeholder' in options.get('data', b'') for _,options in self.calls))
        self.assertFalse(any('unit-test-placeholder' in ' '.join(args) for args,_ in self.calls))

    def test_controller_disables_core_dumps_before_reading_any_secret_input(self):
        import resource
        events=[]
        with patch.object(resource,'setrlimit',side_effect=lambda *args:events.append(args)), patch.object(c.os,'umask'), patch.object(c.os,'geteuid',return_value=1234):
            with self.assertRaises(c.Refused): c.main()
        self.assertEqual(events,[(resource.RLIMIT_CORE,(0,0))])

    def test_failed_crypto_subprocess_diagnostics_are_never_relayed(self):
        result = types.SimpleNamespace(returncode=1, stdout=b'', stderr=b'unit-test-placeholder')
        # Exercise the real command boundary, rather than the setup service mock.
        patch.stopall()
        with patch.object(c.subprocess, 'run', return_value=result):
            with self.assertRaises(c.Refused) as caught: c.run(['systemd-creds', 'encrypt'])
        self.assertNotIn('unit-test-placeholder', str(caught.exception))

class AccountTests(unittest.TestCase):
    def test_node_and_provider_proxy_cannot_share_root_or_each_other(self):
        for left,right in [(0,1000),(1000,0),(1000,1000)]:
            values = [types.SimpleNamespace(pw_uid=left,pw_gid=1000),types.SimpleNamespace(pw_uid=right,pw_gid=1001)]
            with patch.object(c.pwd,'getpwnam',side_effect=values):
                with self.assertRaises(c.Refused): c.validate_accounts({'family':'base'})


class ReadinessTests(unittest.TestCase):
    def fixture(self):
        expected = {'chain_id':11155420, 'l1_chain_id':11155111, 'anchor':{'number':0, 'hash':'0x'+'a'*64}}
        refs = {label:{'number':number, 'hash':'0x'+letter*64, 'timestamp':99990} for label,number,letter in [('unsafe_l2',100,'b'),('safe_l2',99,'c'),('finalized_l2',98,'d')]}
        observed = {'chain_id':hex(expected['chain_id']), 'syncing':False, 'latest':{'number':hex(100),'timestamp':hex(100000)},
                    'rollup':{'l1_chain_id':expected['l1_chain_id'],'l2_chain_id':expected['chain_id'],'genesis':{'l2':expected['anchor']}},
                    'consensus_sync':dict(refs,current_l1={'number':1000,'timestamp':100000}), 'canonical_safe':{'hash':refs['safe_l2']['hash']},
                    'canonical_finalized':{'hash':refs['finalized_l2']['hash']}, 'l1_chain_id':hex(expected['l1_chain_id']), 'l1_head':hex(1000)}
        services = {role:'active' for role in ['execution','consensus','rpc','upstreams']}
        return expected, observed, services
    def test_readiness_requires_network_sync_recent_tip_and_canonical_finality(self):
        expected, observed, services = self.fixture()
        self.assertTrue(s.evaluate(observed,expected,services,100001)['ready'])
        for field,value in [('chain_id','0x1'),('syncing',{}),('latest',{'number':'0x64','timestamp':'0x1'}),
                            ('consensus_sync',{}),('l1_head',hex(2000)),('canonical_safe',{'hash':'0x'+'e'*64}),('l1_chain_id',None),('rollup',{})]:
            invalid = copy.deepcopy(observed); invalid[field] = value
            self.assertFalse(s.evaluate(invalid,expected,services,100001)['ready'], field)
    def test_missing_hashes_or_boolean_heights_cannot_look_healthy(self):
        expected, observed, services = self.fixture()
        observed['canonical_safe']['hash'] = None; observed['consensus_sync']['safe_l2']['hash'] = None
        self.assertFalse(s.evaluate(observed,expected,services,100001)['ready'])
        expected, observed, services = self.fixture()
        observed['consensus_sync']['unsafe_l2']['number'] = True
        self.assertFalse(s.evaluate(observed,expected,services,100001)['ready'])
    def test_reth_structured_status_needs_stages_not_just_equal_current_and_highest(self):
        expected, observed, services = self.fixture()
        observed['syncing'] = {'startingBlock':'0x0','currentBlock':'0x64','highestBlock':'0x64',
                               'stages':[{'name':name,'block':'0x64'} for name in ['Headers','Bodies','Execution','MerkleExecute','Finish']]}
        self.assertTrue(s.evaluate(observed,expected,services,100001)['ready'])
        for bad in [{}, {'startingBlock':'0x0','currentBlock':'0x64','highestBlock':'0x64'},
                    dict(observed['syncing'],highestBlock='0x65'), dict(observed['syncing'],stages=[{'name':'Finish','block':'0x64'}])]:
            invalid = copy.deepcopy(observed); invalid['syncing'] = bad
            self.assertFalse(s.evaluate(invalid,expected,services,100001)['ready'])
        incomplete = {'startingBlock':'0x0','currentBlock':'0x1000','highestBlock':'0x1000',
                      'stages':[{'name':'Execution','block':'0x1'},{'name':'Finish','block':'0x1'}]}
        self.assertFalse(s.execution_synced(incomplete, {'number':'0x1000'}))

    def test_gateway_readiness_has_no_self_dependency(self):
        expected, observed, services = self.fixture(); services['rpc'] = 'inactive'
        self.assertTrue(s.evaluate(observed,expected,services,100001,gateway=False)['ready'])
        self.assertFalse(s.evaluate(observed,expected,services,100001,gateway=True)['ready'])

class ReleaseTests(unittest.TestCase):
    def test_bad_digest_prevents_signature_processing_and_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); archive = root/'artifact'; archive.write_bytes(b'inert archive')
            with patch.object(install, 'call') as called:
                with self.assertRaises(ValueError): install.base_archive(archive,root/'sig',root/'key','a'*64,'base-reth-node',root/'binary')
                called.assert_not_called()
            self.assertFalse((root/'binary').exists())
    def test_signature_policy_rejects_wrong_weak_expired_or_absent_signer(self):
        valid = '[GNUPG:] VALIDSIG '+install.SIGNER+' 2026-10-22 1 0 4 0 1 8 00 '+install.SIGNER
        install.signature(valid)
        for bad in ['',valid.replace(' 8 00 ',' 2 00 '),valid.replace(install.SIGNER,'A'*40),valid+'\n[GNUPG:] EXPKEYSIG x']:
            with self.assertRaises(ValueError): install.signature(bad)

class ExtractionTests(unittest.TestCase):
    def tar(self, name, link=None):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as archive:
            member = tarfile.TarInfo(name)
            if link:
                member.type = tarfile.SYMTYPE; member.linkname = link; archive.addfile(member)
            else:
                member.size = 10; archive.addfile(member, io.BytesIO(b'inert data'))
        stream.seek(0); return stream
    def extract(self, stream, destination):
        decoder = Mock(stdout=stream); decoder.wait.return_value = 0; decoder.poll.return_value = 0
        with patch.object(b.subprocess, 'Popen', return_value=decoder), patch.object(b.os, 'geteuid', return_value=1000):
            b.extract_op(Path('synthetic-archive'), destination)
    def test_real_tar_extractor_resumes_without_path_escape_or_links(self):
        with tempfile.TemporaryDirectory() as folder:
            data = Path(folder)/'data'; data.mkdir()
            self.extract(self.tar('db/database.version'), data)
            self.extract(self.tar('db/database.version'), data)
            self.assertEqual((data/'db/database.version').read_bytes(), b'inert data')
            for name, link in [('../outside',None), ('/outside',None), ('db/alias','../outside')]:
                with self.assertRaises(c.Refused): self.extract(self.tar(name, link), data)
            self.assertFalse((Path(folder)/'outside').exists())

if __name__ == '__main__': unittest.main()

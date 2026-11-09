# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Offline host-controller failure injection; no daemon, wallet or network."""
import copy
import importlib.util
import json
import os
import hashlib
import io
import tarfile
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location('bitcoin_control', Path(sys.argv.pop(1)).resolve())
c = importlib.util.module_from_spec(spec)
original = Path(sys.argv[0]).resolve().parents[1] / 'templates/node/original.py'
exec(compile(original.read_bytes(), str(original), 'exec'), c.__dict__)
migration = original.with_name('migration.py')
exec(compile(migration.read_bytes(),str(migration),'exec'),c.__dict__)
processes = original.with_name('processes.py')
exec(compile(processes.read_bytes(), str(processes), 'exec'), c.__dict__)
spec.loader.exec_module(c)
ORIGINAL_PROPERTIES = c.service_properties
ORIGINAL_RUNTIME = c.original_runtime
ORIGINAL_CLI = c.cli
ORIGINAL_DRAIN = c.drain_original
ORIGINAL_DISABLE = c.disable_original_boot
ORIGINAL_RETAINED_ORIGIN = c.retained_origin
SHIPPED_CATALOG = copy.deepcopy(c.CATALOG)


class HostTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.addCleanup(patch.stopall)
        root = Path(temp.name).resolve()
        # The directories containing the temporary root are not system paths.
        # Model their protected ancestry, retaining every mode inside the root.
        outside = {(info.st_dev, info.st_ino) for info in map(os.stat, root.parents)}
        actual = os.lstat
        def lstat(path, *args, **kwargs):
            info = actual(path, *args, **kwargs)
            if (info.st_dev, info.st_ino) not in outside:
                return info
            fields = list(info); fields[0] &= ~0o022
            return os.stat_result(fields)
        patch.object(os, 'lstat', lstat).start()
        patch.object(Path, 'lstat', lambda path: lstat(path)).start()
        patch.object(c, 'ROOT_UID', os.getuid()).start()
        patch.object(c, 'ROOT_GID', os.getgid()).start()
        patch.object(c,'original_runtime',return_value={'uid':os.getuid(),'gid':os.getgid(),
                     'name':'inert-account','home':str(root/'root/data'),'shell':'/usr/sbin/nologin'}).start()
        patch.object(c, 'HELPER', root / 'controller').start()
        patch.object(c, 'UNIT_PATH', root / 'unit.service').start()
        patch.object(c.grp, 'getgrnam', return_value=type('Group', (), {'gr_gid':os.getgid()})()).start()
        patch.object(c, 'ROOT', root / 'root').start()
        patch.object(c, 'OPT', root / 'opt').start()
        patch.object(c, 'CONF', root / 'bitcoin.conf').start()
        patch.object(c, 'LOCK', root / 'lock').start()
        patch.object(c,'PROC',root/'proc').start();c.PROC.mkdir()
        c.ROOT.mkdir()
        c.OPT.mkdir()
        self.pin = {'version': '31.1', 'commit': 'a' * 40, 'sha256': 'b' * 64, 'platform': 'x86_64-linux-gnu'}
        archive = c.OPT / 'bitcoin-31.1-x86_64-linux-gnu.tar.gz'
        with tarfile.open(archive, 'w:gz') as target:
            for name in ('bitcoind','bitcoin-cli'):
                raw = ('inert fixture ' + name).encode()
                info = tarfile.TarInfo('bitcoin-31.1/bin/' + name)
                info.size = len(raw); info.mode = 0o755
                target.addfile(info, io.BytesIO(raw))
        self.pin['sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
        # Inert extra catalog entries exercise interrupted future transitions;
        # they are not executable releases shipped by the production catalog.
        patch.object(c,'CATALOG',{version:{'commit':self.pin['commit'],
            'artifacts':{self.pin['platform']:self.pin['sha256']}} for version in ('31.1','32.0','33.0')}).start()
        self.state = {'owner': 'sourceowner', 'network': 'signet', 'storage': 'full', 'prune_mib': 0, 'phase': 'installed', 'installed': self.pin}
        c.CONF.write_text(c.configuration(self.state))
        (c.ROOT / 'data').mkdir()
        (c.ROOT / 'data/chainstate-fixture').write_text('persistent-state')
        self.state.update(machine_sha256='c'*64,source_started=True,data_ready=True,origin='fresh',
            layout={'root':{'uuid':'00000000-0000-0000-0000-000000000001','fstype':'ext4'},
                    'data':{'uuid':'00000000-0000-0000-0000-000000000001','fstype':'ext4'},
                    'root_inode':c.ROOT.stat().st_ino,'data_inode':(c.ROOT/'data').stat().st_ino})
        account={'name':'erpc-bitcoin','uid':os.getuid(),'gid':os.getgid(),
                 'home':str(c.ROOT/'data'),'shell':'/usr/sbin/nologin'}
        c.original_write('account-intent.json',{'contract':c.contract(self.state),'account':account})
        c.original_write('account.json',{'contract':c.contract(self.state),'account':account})
        directory = c.release_dir(self.pin)
        directory.mkdir(parents=True)
        (directory/'bin').mkdir()
        for native in ('bitcoind','bitcoin-cli'):
            (directory/'bin'/native).write_text('inert fixture '+native)
            (directory/'bin'/native).chmod(0o755)
        (directory / 'verified.json').write_text(json.dumps(self.pin))
        (c.OPT / 'current').symlink_to(directory)
        c.register_native(self.state,self.pin,
            hashlib.sha256((directory/'bin/bitcoind').read_bytes()).hexdigest(),
            hashlib.sha256((directory/'bin/bitcoin-cli').read_bytes()).hexdigest())
        c.original_write('source-floor.json',{'scope':c.runtime_scope(self.state),'source':c.native_key(self.pin)})
        initial_unit=Path(c.__file__).with_name('erpc-bitcoin.service').read_text().replace('@BITCOIN_UID@',str(os.getuid())).replace('@BITCOIN_GID@',str(os.getgid()))
        c.UNIT_PATH.write_text(initial_unit)
        initial_digest=hashlib.sha256(initial_unit.encode()).hexdigest()
        self.state.update(unit_sha256=initial_digest,unit_receipts=[initial_digest])
        c.save(self.state)
        self.calls = []
        self.request_generation = 0
        self.service = 'active'
        self.free = 200_000_000_000
        patch.object(c.shutil, 'disk_usage', side_effect=lambda _: type('Usage', (), {'free': self.free})()).start()
        def run(args, **kwargs):
            self.calls.append(args)
            if args[:2] == ['/usr/bin/systemctl', 'stop']:
                self.service = 'inactive'
            if args[:2] == ['/usr/bin/systemctl', 'start']:
                self.service = 'active'
            if args[0] == 'tar':
                subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if args[-1] == '--version':
                return b'Bitcoin Core daemon version v31.1 bitcoind\npublic license text\n'
            return b'0' 
        self.service_run = run
        patch.object(c, 'run', side_effect=run).start()
        patch.object(c, 'loaded', return_value=True).start()
        patch.object(c, 'active', side_effect=lambda: self.service).start()
        def properties():
            value={key:'' for key in c.SERVICE_FIELDS}
            value.update(LoadState='loaded',FragmentPath=str(c.UNIT_PATH),NoNewPrivileges='yes',
                         ActiveState=self.service,MainPID='0')
            raw=c.UNIT_PATH.read_text()
            for field in ('User','Group'):
                value[field]=next(line.partition('=')[2] for line in raw.splitlines() if line.startswith(field+'='))
            for field in ('ExecStart','ExecStartPre'):
                line=next(line.partition('=')[2] for line in raw.splitlines() if line.startswith(field+'='))
                args=c.shlex.split(line.lstrip('+'))
                value[field]='{ path='+args[0]+' ; argv[]='+' '.join(args)+' ; ignore_errors=no ; pid=0 }'
            return value
        patch.object(c,'service_properties',side_effect=properties).start()
        patch.object(c, 'cli', side_effect=c.Refused('warming up')).start()
        patch.object(c, 'running_process', return_value={'pid':1234,'start':'1'}).start()
        def drained(_state):
            if c.loaded():
                c.run(['/usr/bin/systemctl','stop',c.UNIT])
                c.require(c.active() in ('inactive','failed','unknown'),'inert service remains active')
        patch.object(c,'drain_original',side_effect=drained).start()
        patch.object(c,'drain_legacy',side_effect=lambda:drained({})).start()
        patch.object(c,'disable_original_boot',side_effect=lambda _state:c.run(['/usr/bin/systemctl','disable',c.UNIT]) if c.loaded() else None).start()
        patch.object(c,'retained_origin',return_value=None).start()

    def request(self, action, **updates):
        unit = Path(c.__file__).with_name('erpc-bitcoin.service').read_text().replace('@BITCOIN_UID@',str(os.getuid())).replace('@BITCOIN_GID@',str(os.getgid()))
        if 'generation' not in updates:
            updates['generation']=self.request_generation
        return dict(c.contract(self.state), pin=copy.deepcopy(self.pin), action=action, intent='a'*32, unit=unit,
                    controller_sha256=hashlib.sha256(Path(c.__file__).read_bytes()).hexdigest(), **updates)

    def begin(self, request=None):
        request = request or self.request('begin-install')
        request['generation']=c.generation(c.read_state())
        self.request_generation=request['generation']
        c.locked(dict(request, action='authorize'))
        return c.locked(request)

    def test_every_mutator_refuses_wrong_owner_network_and_retention_before_any_action(self):
        for action in ['authorize', 'begin-install', 'install-artifacts', 'activate', 'start', 'stop', 'restart', 'destroy']:
            for field, wrong in [('owner', 'otherowner'), ('network', 'mainnet'), ('storage', 'pruned')]:
                request = self.request(action)
                request[field] = wrong
                if field == 'storage':
                    request['prune_mib'] = 10240
                before = (c.ROOT / 'owner.json').read_bytes()
                with self.assertRaises(c.Refused):
                    c.locked(request)
                self.assertEqual(self.calls, [])
                self.assertEqual((c.ROOT / 'owner.json').read_bytes(), before)
        self.assertEqual((c.ROOT / 'data/chainstate-fixture').read_text(), 'persistent-state')

    def test_failed_cross_network_init_cannot_stop_or_retire_original_node(self):
        wrong = self.request('prepare')
        wrong.update(owner='newinventoryitem', network='testnet4')
        with self.assertRaises(c.Refused):
            c.locked(wrong)
        for action in ['start', 'stop', 'restart', 'destroy']:
            wrong['action'] = action
            with self.assertRaises(c.Refused):
                c.locked(wrong)
        self.assertEqual(c.read_state()['network'], 'signet')
        self.assertEqual(self.calls, [])
        self.assertEqual(self.service, 'active')

    def test_changed_rpc_config_cannot_be_used_on_start_or_reboot(self):
        c.CONF.write_text(c.CONF.read_text().replace('rpcbind=127.0.0.1', 'rpcbind=0.0.0.0'))
        with self.assertRaises(c.Refused):
            c.guard(self.state)
        for action in ['start', 'restart', 'begin-install']:
            with self.assertRaises(c.Refused):
                c.locked(self.request(action))
        self.assertEqual(self.calls, [])

    def test_interrupted_update_keeps_install_fence_and_refuses_new_target_or_downgrade(self):
        request = self.request('begin-install')
        request['pin']['version'] = '32.0'
        self.begin(request)
        current = c.read_state()
        self.assertEqual(current['phase'], 'installing')
        with self.assertRaises(c.Refused):
            c.guard(current)
        c.locked(request)  # same target is a safe retry
        for version in ['31.1', '33.0']:
            different = copy.deepcopy(request)
            different['pin']['version'] = version
            with self.assertRaises(c.Refused):
                c.locked(different)
        for action in ['start', 'restart']:
            with self.assertRaises(c.Refused):
                c.locked(self.request(action))
        self.assertEqual(c.read_state()['installed']['version'], '31.1')
        self.assertEqual((c.ROOT / 'data/chainstate-fixture').read_text(), 'persistent-state')

    def test_failed_stop_during_update_still_blocks_reboot(self):
        with patch.object(c, 'stop', side_effect=c.Refused('shutdown failed')):
            with self.assertRaises(c.Refused):
                self.begin()
        self.assertEqual(c.read_state()['phase'], 'installing')
        with self.assertRaises(c.Refused):
            c.guard(c.read_state())

    def test_emergency_stop_and_retirement_cancel_an_interrupted_installation(self):
        for operation in ('stop', 'destroy'):
            with self.subTest(operation=operation):
                c.save(self.state)
                for name in ('cancelled.json','cancelled.json.new','owner.json.new'): (c.ROOT/name).unlink(missing_ok=True)
                request = self.request('begin-install')
                with patch.object(c, 'stop', side_effect=c.Refused('inert shutdown fault')):
                    with self.assertRaises(c.Refused):
                        self.begin(request)
                self.service = 'active'
                self.calls.clear()
                c.locked(self.request(operation))
                self.assertEqual(self.service, 'inactive')
                self.assertIn(['/usr/bin/systemctl', 'disable', c.UNIT], self.calls)
                self.calls.clear()
                before = (c.ROOT / 'owner.json').read_bytes()
                for stale in ('begin-install', 'install-artifacts', 'activate'):
                    with self.assertRaises(c.Refused):
                        c.locked(dict(request, action=stale))
                self.assertEqual(self.calls, [])
                self.assertEqual((c.ROOT / 'owner.json').read_bytes(), before)
                self.assertEqual((c.ROOT / 'data/chainstate-fixture').read_text(), 'persistent-state')

    def test_real_fsync_failure_never_skips_shutdown_or_revives_a_queued_authorization(self):
        original_fsync = os.fsync
        for operation in ('stop', 'destroy'):
            for fault_at in range(1, 5):
                with self.subTest(operation=operation, fault_at=fault_at):
                    c.save(self.state)
                    for name in ('cancelled.json','cancelled.json.new','owner.json.new'): (c.ROOT/name).unlink(missing_ok=True)
                    generation = c.generation(c.read_state())
                    stale = self.request('authorize', generation=generation)
                    self.service = 'active'; self.calls.clear()
                    count = 0
                    def fail(fd):
                        nonlocal count
                        count += 1
                        if count == fault_at:
                            raise OSError('inert durability fault')
                        return original_fsync(fd)
                    with patch.object(c.os, 'fsync', side_effect=fail), self.assertRaises(c.Refused):
                        c.locked(self.request(operation))
                    self.assertEqual(self.service, 'inactive')
                    self.assertIn(['/usr/bin/systemctl', 'disable', c.UNIT], self.calls)
                    with self.assertRaises(c.Refused):
                        c.guard(c.read_state())
                    with self.assertRaises(c.Refused):
                        c.locked(stale)
                    self.assertEqual((c.ROOT / 'data/chainstate-fixture').read_text(), 'persistent-state')

    def test_cancelled_download_cannot_publish_then_a_new_explicit_intent_can_resume(self):
        self.begin()
        c.locked(self.request('stop'))
        original_unit = c.UNIT_PATH.exists()
        original_helper = c.HELPER.read_bytes() if c.HELPER.exists() else None
        with self.assertRaises(c.Refused):
            c.locked(self.request('install-artifacts'))
        self.assertEqual(c.UNIT_PATH.exists(), original_unit)
        self.assertEqual(c.HELPER.read_bytes() if c.HELPER.exists() else None,original_helper)
        self.assertEqual(self.service, 'inactive')
        request = self.request('begin-install')
        request['intent'] = 'b' * 32
        self.begin(request)
        c.locked(dict(request, action='install-artifacts'))
        self.assertEqual(self.service, 'inactive')
        self.assertTrue(c.UNIT_PATH.is_file())
        self.assertEqual(c.HELPER.read_bytes(),Path(c.__file__).read_bytes())
        with self.assertRaises(c.Refused):
            c.locked(self.request('activate'))
        c.locked(dict(request, action='activate'))
        self.assertEqual(self.service, 'active')

    def test_old_manual_start_cannot_clear_a_later_stop(self):
        old = self.request('start', generation=c.generation(c.read_state()))
        c.locked(self.request('stop'))
        self.calls.clear()
        with self.assertRaises(c.Refused):
            c.locked(old)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.service, 'inactive')
        current = self.request('start', generation=c.generation(c.read_state()))
        c.locked(current)
        self.assertEqual(self.service, 'active')

    def test_generation_still_rejects_old_stages_if_a_later_caller_reuses_the_nonce(self):
        old=self.request('begin-install');self.begin(old)
        c.locked(self.request('stop'))
        new=dict(old,generation=c.generation(c.read_state()))
        c.locked(dict(new,action='authorize'))
        self.calls.clear()
        for action in ('begin-install','install-artifacts','activate'):
            with self.assertRaises(c.Refused):c.locked(dict(old,action=action))
        self.assertEqual(self.calls,[])
        c.locked(dict(new,action='begin-install'))
        c.locked(dict(new,action='install-artifacts'))
        self.calls.clear()
        with self.assertRaises(c.Refused):c.locked(dict(old,action='activate'))
        self.assertEqual(self.calls,[])
        c.locked(dict(new,action='activate'))
        self.assertEqual(self.service,'active')

    def test_cancellation_checks_scope_but_does_not_require_healthy_configuration(self):
        c.CONF.write_text('inert invalid configuration')
        c.locked(self.request('stop'))
        self.assertEqual(self.service, 'inactive')
        self.assertEqual(c.CONF.read_text(), 'inert invalid configuration')

    def test_owner_root_and_file_permission_drift_refuse_before_shutdown(self):
        for path in (c.ROOT, c.ROOT / 'owner.json'):
            old = path.stat().st_mode & 0o777
            path.chmod(0o777)
            self.calls.clear()
            with self.assertRaises(c.Refused):
                c.locked(self.request('stop'))
            self.assertEqual(self.calls, [])
            path.chmod(old)

    def test_unsafe_directory_above_the_release_refuses_start_and_boot_with_nothing_changed(self):
        # The fixture's own releases directory is checked only as an ancestor
        # of the protected release, never as a protected path of its own.
        releases = c.OPT / 'releases'
        moved = c.OPT / 'moved-releases'
        mode = releases.stat().st_mode & 0o777
        modelled = Path.lstat
        def foreign(path):
            info = modelled(path)
            if path != releases:
                return info
            fields = list(info); fields[4] = os.getuid() + 1
            return os.stat_result(fields)
        foreign_owner = patch.object(Path, 'lstat', foreign)
        for name, change, restore in [
                ('group-writable', lambda: releases.chmod(mode | 0o020), lambda: releases.chmod(mode)),
                ('other-writable', lambda: releases.chmod(mode | 0o002), lambda: releases.chmod(mode)),
                ('foreign-owned', foreign_owner.start, foreign_owner.stop),
                ('symlink', lambda: (releases.rename(moved), releases.symlink_to(moved)),
                 lambda: (releases.unlink(), moved.rename(releases)))]:
            with self.subTest(name):
                before = {path.name: path.read_bytes() for path in c.ROOT.iterdir() if path.is_file()}
                start = self.request('start', generation=c.generation(c.read_state()))
                self.calls.clear()
                change()
                try:
                    with self.assertRaisesRegex(c.Refused, 'unsafe protected ancestor'):
                        c.locked(start)
                    with self.assertRaisesRegex(c.Refused, 'unsafe protected ancestor'):
                        c.guard(c.read_state())
                finally:
                    restore()
                self.assertEqual(self.calls, [])
                self.assertEqual({path.name: path.read_bytes() for path in c.ROOT.iterdir() if path.is_file()}, before)
        c.guard(c.read_state())
        c.locked(self.request('start', generation=c.generation(c.read_state())))
        self.assertIn(['/usr/bin/systemctl', 'start', c.UNIT], self.calls)

    def test_legacy_partial_installation_without_original_volume_authority_is_retained(self):
        c.CONF.unlink()
        fresh = c.contract(self.state)
        fresh['phase'] = 'prepared'
        c.save(fresh)
        for name in ('account-intent.json','account.json','native-releases.json','source-floor.json'):
            (c.ROOT/name).unlink()
        with patch.object(c, 'loaded', return_value=False):
            self.begin()
            with self.assertRaises(c.Refused): c.locked(self.request('prepare'))
            self.begin()
        self.assertEqual(c.read_state()['phase'], 'installing')
        self.assertEqual(self.calls, [])

    def test_install_completion_needs_exact_verified_target(self):
        self.begin()
        archive = c.OPT / 'bitcoin-31.1-x86_64-linux-gnu.tar.gz'
        saved = archive.read_bytes()
        archive.unlink()
        with self.assertRaises((c.Refused, FileNotFoundError)):
            c.locked(self.request('install-artifacts'))
        self.assertEqual(c.read_state()['phase'], 'installing')
        archive.write_bytes(saved)
        c.locked(self.request('install-artifacts'))
        with self.assertRaises(c.Refused):
            c.guard(c.read_state())
        self.assertNotIn(['/usr/bin/systemctl', 'start', c.UNIT], self.calls)

    def test_retire_preserves_data_and_ownership_but_blocks_boot(self):
        c.locked(self.request('destroy'))
        self.assertEqual(c.read_state()['phase'], 'retired')
        self.assertEqual(c.read_state()['owner'], self.state['owner'])
        self.assertEqual((c.ROOT / 'data/chainstate-fixture').read_text(), 'persistent-state')
        with self.assertRaises(c.Refused):
            c.guard(c.read_state())
        self.assertEqual(self.service, 'inactive')

    def test_unowned_existing_daemon_is_not_adopted(self):
        (c.ROOT / 'owner.json').unlink()
        with self.assertRaises(c.Refused):
            c.locked(self.request('prepare'))
        self.assertFalse((c.ROOT / 'owner.json').exists())
        self.assertEqual(self.calls, [])

    def test_status_does_not_claim_warmup_rpc_is_ready(self):
        status = c.locked(self.request('status'))
        self.assertFalse(status['rpc_available'])
        self.assertIn('warming up', status['inspection_error'])

    def test_failed_low_space_init_cannot_be_bypassed_by_deploy(self):
        (c.ROOT / 'owner.json').unlink()
        (c.ROOT / 'data/chainstate-fixture').unlink()
        (c.ROOT / 'data').rmdir()
        self.free = 1
        with patch.object(c, 'loaded', return_value=False):
            with self.assertRaises(c.Refused):
                c.locked(self.request('prepare'))
        self.assertFalse((c.ROOT / 'owner.json').exists())
        for action in ('prepare', 'begin-install'):
            with patch.object(c, 'loaded', return_value=False), self.assertRaises(c.Refused):
                c.locked(self.request(action))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.service, 'active')

    def test_later_low_space_blocks_update_resume_start_and_reboot_without_stopping(self):
        self.free = 1
        before = (c.ROOT / 'owner.json').read_bytes()
        for action in ('prepare', 'begin-install', 'start', 'restart'):
            with self.assertRaises(c.Refused):
                c.locked(self.request(action))
        with self.assertRaises(c.Refused):
            c.guard(c.read_state())
        self.assertEqual(self.calls, [])
        self.assertEqual((c.ROOT / 'owner.json').read_bytes(), before)
        self.free = 200_000_000_000
        self.begin()
        self.calls.clear()
        self.free = 1
        with self.assertRaises(c.Refused):
            self.begin()
        self.assertEqual(self.calls, [])
        self.assertEqual(c.read_state()['phase'], 'installing')
        c.locked(self.request('status'))  # inspection stays available

    def test_real_database_allocation_reduces_sync_floor_but_never_operating_headroom(self):
        database = c.ROOT / 'data/signet/blocks'
        database.mkdir(parents=True)
        self.free = 60_000_000_000
        with patch.object(c, 'run', return_value=b'60000000000 database') as measured:
            c.capacity(c.read_state())
            self.assertEqual(measured.call_args.args[0][:3], ['/usr/bin/du', '-sx', '-B1'])
            self.free = 49_000_000_000
            with self.assertRaises(c.Refused):
                c.capacity(c.read_state())
        self.free = 200_000_000_000
        database.rmdir()
        database.symlink_to(c.ROOT)
        with self.assertRaises(c.Refused):
            c.capacity(c.read_state())

    def test_large_prune_target_and_unpopulated_installed_state_do_not_skip_sync_floor(self):
        state = c.read_state()
        state.update(storage='pruned', prune_mib=1_000_000)
        self.free = 110_000_000_000
        with self.assertRaises(c.Refused):
            c.capacity(state)
        self.free = 1_200_000_000_000
        c.capacity(state)
        state.update(network='mainnet', storage='full', prune_mib=0)
        self.free = 100_000_000_000
        with self.assertRaises(c.Refused):
            c.capacity(state)  # phase installed alone is never sync evidence

    def test_hostile_dynamic_settings_are_disabled_in_the_real_daemon_unit(self):
        import shlex
        directory = c.ROOT / 'data/signet'
        directory.mkdir()
        hostile = {'rpcbind': ['0.0.0.0'], 'rpcallowip': ['0.0.0.0/0'], 'disablewallet': False, 'prune': 550, 'txindex': False}
        (directory / 'settings.json').write_text(json.dumps(hostile))
        unit = Path(c.__file__).with_name('erpc-bitcoin.service').read_text()
        argv = shlex.split(next(line.split('=', 1)[1] for line in unit.splitlines() if line.startswith('ExecStart=')))
        # Core 31.1 common/init.cpp gates ReadSettingsFile on GetSettingsPath;
        # command-line -nosettings disables that path before dynamic overrides.
        self.assertIn('-nosettings', argv)
        self.assertFalse(any(arg.startswith('-settings=') for arg in argv))
        self.assertIn('-conf=/etc/erpc/bitcoin.conf', argv)
        c.guard(c.read_state())
        self.assertEqual(json.loads((directory / 'settings.json').read_text()), hostile)


class PendingCancellationTests(unittest.TestCase):
    def test_both_pre_rename_file_sync_failures_revoke_delayed_stages_and_keep_retirement(self):
        for operation in ('stop','destroy'):
            for published in (False,True):
                with self.subTest(operation=operation,published=published):
                    fixture=HostTests('runTest');fixture.setUp()
                    try:
                        query=fixture.request('begin-install');fixture.begin(query)
                        if published:c.locked(dict(query,action='install-artifacts'))
                        fixture.service='active';fixture.calls.clear()
                        original=os.fsync;failed=set()
                        def fault(descriptor):
                            opened=os.fstat(descriptor)
                            for name in ('cancelled.json.new','owner.json.new'):
                                path=c.ROOT/name
                                if path.exists() and path.stat().st_ino==opened.st_ino and name not in failed:
                                    failed.add(name);raise OSError('inert first file barrier failure')
                            return original(descriptor)
                        with patch.object(c.os,'fsync',side_effect=fault),self.assertRaises(c.Refused):
                            c.locked(fixture.request(operation))
                        self.assertEqual(failed,{'cancelled.json.new','owner.json.new'})
                        self.assertEqual(fixture.service,'inactive')
                        self.assertIn(['/usr/bin/systemctl','disable',c.UNIT],fixture.calls)
                        for name in failed:self.assertTrue((c.ROOT/name).is_file())
                        floor=c.generation(c.read_state());fixture.calls.clear()
                        if operation=='destroy':
                            with self.assertRaises(c.Refused):c.locked(fixture.request('start',generation=floor))
                        for action in ('prepare','begin-install','install-artifacts','activate','authorize'):
                            with self.assertRaises(c.Refused):c.locked(dict(query,action=action))
                        with self.assertRaises(c.Refused):c.guard(c.read_state())
                        self.assertEqual(fixture.calls,[])
                        # A stop retry retains a pending destroy's retirement.
                        c.locked(fixture.request('stop'))
                        self.assertGreater(c.generation(c.read_state()),floor)
                        if operation=='destroy':self.assertEqual(c.read_state()['phase'],'retired')
                        fresh=fixture.request('begin-install',generation=c.generation(c.read_state()))
                        fresh['intent']='c'*32
                        fixture.begin(fresh)
                        for name in failed:self.assertFalse((c.ROOT/name).exists())
                        c.locked(dict(fresh,action='install-artifacts'))
                        c.locked(dict(fresh,action='activate'))
                        self.assertEqual(fixture.service,'active')
                        self.assertEqual((c.ROOT/'data/chainstate-fixture').read_text(),'persistent-state')
                    finally:fixture.doCleanups()

    def test_pending_owner_alone_fences_and_failed_new_authorization_cannot_clear_it(self):
        fixture=HostTests('runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        query=fixture.request('begin-install');fixture.begin(query)
        restricted=dict(c.read_state(),phase='v3:retired',stopped=True,intent=None,generation=2)
        (c.ROOT/'owner.json.new').write_text(json.dumps(restricted))
        self.assertTrue(c.stopped());self.assertEqual(c.generation(c.read_state()),2)
        with self.assertRaises(c.Refused):c.locked(dict(query,action='install-artifacts'))
        fresh=fixture.request('authorize',generation=2)
        real=os.fsync
        def fault(descriptor):
            path=c.ROOT/'owner.json.new'
            if path.exists() and os.fstat(descriptor).st_ino==path.stat().st_ino:raise OSError('inert replacement barrier')
            return real(descriptor)
        with patch.object(c.os,'fsync',side_effect=fault),self.assertRaises(OSError):c.locked(fresh)
        self.assertTrue(c.stopped());self.assertEqual(c.generation(c.read_state()),3)
        for action in ('begin-install','install-artifacts','activate'):
            with self.assertRaises(c.Refused):c.locked(dict(fresh,action=action))
        with self.assertRaises(c.Refused):c.clear_cancellation()
        self.assertTrue((c.ROOT/'owner.json.new').exists())

    def test_malformed_or_foreign_pending_records_never_authorize_continuation(self):
        fixture=HostTests('runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        query=fixture.request('begin-install');fixture.begin(query)
        original=c.read_state()
        for name,raw in [('cancelled.json.new','{'),('owner.json.new','{'),
                         ('owner.json.new',json.dumps(dict(original,owner='foreign',phase='v3:installed')))]:
            path=c.ROOT/name;path.write_text(raw)
            with self.assertRaises((c.Refused,ValueError)):c.locked(dict(query,action='install-artifacts'))
            path.unlink()


class CliBoundaryTests(unittest.TestCase):
    def test_inspection_uses_bound_http_transport_not_native_cli(self):
        fixture = HostTests('runTest'); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        with patch.object(c,'inspect_rpc',return_value={'chain':'signet'}) as inspection:
            self.assertEqual(ORIGINAL_CLI('getblockchaininfo'), {'chain':'signet'})
            inspection.assert_called_once_with(c.read_state(),'getblockchaininfo',())
        self.assertEqual(fixture.calls,[])


class ArtifactTests(unittest.TestCase):
    def test_native_version_uses_the_pinned_daemon_format_and_exact_release(self):
        for spelling in ('31.1', '31.1.0'):
            c.native_version(('Bitcoin Core daemon version v' + spelling + ' bitcoind\nlicense\n').encode(), '31.1')
        for invalid in (b'Bitcoin Core version v31.1', b'Bitcoin Core daemon version v31.10 bitcoind',
                        b'Bitcoin Core daemon version v31.1rc1 bitcoind',
                        b'Bitcoin Core daemon version v31.1 bitcoin-node',
                        b'prefix Bitcoin Core daemon version v31.1 bitcoind', b''):
            with self.assertRaises(c.Refused):
                c.native_version(invalid, '31.1')

    def test_bad_archive_digest_is_refused_before_it_can_be_extracted(self):
        import hashlib
        spec = importlib.util.spec_from_file_location('verification', Path(c.__file__).with_name('verify.py'))
        verification = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verification)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'archive-fixture'
            path.write_bytes(b'public non-executable fixture')
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            verification.verify_archive(path, expected)
            path.write_bytes(b'tampered bytes')
            with self.assertRaises(ValueError):
                verification.verify_archive(path, expected)
            alias = path.with_name('alias')
            alias.symlink_to(path)
            with self.assertRaises(ValueError):
                verification.verify_archive(alias, expected)


if __name__ == '__main__':
    unittest.main()

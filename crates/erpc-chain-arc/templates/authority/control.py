#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Arc original host authority; public requests, original encrypted key delivery."""
import os
import pathlib
import resource
import sys

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
# BEGIN ERPC TRUSTED IMPORTS
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
# Embedded verbatim in helpers that need sibling modules. Startup uses -I;
# only this checked directory is added, after the standard-library paths.
def trusted_imports(directory):
    import os
    import stat
    import sys
    path = os.fspath(directory)
    if not os.path.isabs(path):
        raise ValueError('helper directory must be an absolute path')
    current = os.path.sep
    for part in path.split(os.path.sep)[1:]:
        if part in ('', '.'):
            continue
        if part == '..':
            # The component being left was already checked as a real root-only
            # directory. Never normalize away an unchecked symlink ancestor.
            current = os.path.dirname(current)
            continue
        current = os.path.join(current, part)
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('helper ancestors must be real root-owned directories')
    path = current
    if path == os.path.sep:
        raise ValueError('the filesystem root is not a helper directory')
    # Do not create root0700 bytecode caches before an unprivileged helper
    # imports the same module. Existing readable caches remain fully checked.
    sys.dont_write_bytecode = True
    pending = [path]
    while pending:
        for child in os.scandir(pending.pop()):
            info = child.stat(follow_symlinks=False)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('helper modules must be writable only by root')
            if stat.S_ISDIR(info.st_mode):
                if (child.name == '__pycache__'
                        and not os.access(child.path, os.X_OK, effective_ids=True)):
                    # No traversal means Python cannot read any cached module
                    # here and must use the checked source. Denied listing alone
                    # (e.g. mode0711) is not sufficient for this exception.
                    continue
                pending.append(child.path)
            elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('helper modules cannot be links or special files')
    if path not in sys.path:
        sys.path.append(path)
# END ERPC TRUSTED IMPORTS
if __name__ == '__main__':
    trusted_imports(pathlib.Path(__file__).resolve().parent)

import contextlib
import io
import re
import time
import fcntl
import stat
import subprocess
from arc_files import Files, Refused, digest, encoded, require, strict_json
import arc_accounts as accounts
import arc_custody as custody
import arc_protocol as protocol
import arc_release as release
import arc_storage as storage
import arc_helpers as helpers
import arc_process as process
import arc_units as units
import arc_bootstrap as bootstrap
import arc_observe as observe
import arc_migration as migration

OWNER = '/etc/erpc/arc/authority/owner.json'
SCHEMA = 'erpc-arc-original-authority-v1'


class Control(Files):
    def namespaces(self):
        for name in ('/etc/erpc/arc/authority', '/usr/local/lib/erpc/arc', '/opt/arc',
                     '/etc/systemd/system', '/etc/credstore.encrypted', '/etc/sysctl.d',
                     '/etc/systemd/journald.conf.d'):
            self.protected(name, missing=True, directory=True)
        for unit in ('arc-execution.service', 'arc-consensus.service', 'arc-snapshots.service',
                     'erpc-arc-firewall.service'):
            self.protected('/etc/systemd/system/' + unit, missing=True)
            folder = self.protected('/etc/systemd/system/' + unit + '.d', missing=True, directory=True)
            if folder.exists():
                names = {'50-erpc-firewall-guard.conf', '50-erpc-firewall-guard.conf.new'}
                require(set(os.listdir(folder)) <= names, 'unknown Arc service overrides are present')
                for item in folder.iterdir():
                    self.protected('/etc/systemd/system/' + unit + '.d/' + item.name)
        for name in ('/etc/sysctl.d/90-erpc-arc.conf', '/etc/systemd/journald.conf.d/90-erpc-arc.conf'):
            self.protected(name, missing=True)
        self.protected('/usr/local/lib/erpc/rpc-firewall.py', missing=True)
        self.protected(custody.CREDENTIAL, missing=True)

    def machine(self):
        raw = self.read('/etc/machine-id', limit=128).strip()
        require(len(raw) == 32 and all(byte in b'0123456789abcdef' for byte in raw),
                'original machine identity is unavailable')
        return digest(raw)

    def state(self, wanted):
        protocol.contract(wanted)
        self.namespaces()
        state = self.json(OWNER, private=True)
        require(isinstance(state, dict) and state.get('schema') == SCHEMA and
                state.get('contract') == wanted and state.get('machine') == self.machine(),
                'Arc original owner/network/key/host contract differs')
        return state

    def platform(self):
        os_release = {}
        self.protected('/etc', directory=True)
        path = self.path('/etc/os-release')
        name = '/etc/os-release'
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            require(info.st_uid == self.owner and os.readlink(path) in ('../usr/lib/os-release', '/usr/lib/os-release'),
                    'unexpected operating-system release reference')
            name = '/usr/lib/os-release'
        for line in self.read(name, limit=16384).decode().splitlines():
            if '=' in line and not line.startswith('#'):
                key, value = line.split('=', 1)
                os_release[key] = value.strip().strip('"')
        require(os_release.get('ID') == 'ubuntu' and os_release.get('VERSION_ID') == '24.04',
                'Arc original authority is qualified for Ubuntu 24.04')
        systemd = self.command('/usr/bin/systemctl', '--version').stdout.splitlines()[0].split()
        require(systemd[:2] == [b'systemd', b'255'], 'Arc requires the qualified systemd 255 credential ordering')

    def fresh(self):
        self.platform()
        self.namespaces()
        for name in ('/opt/arc', '/usr/local/lib/erpc/arc'):
            folder = self.protected(name, missing=True, directory=True)
            require(not folder.exists() or not os.listdir(folder),
                    'unowned Arc runtime artifacts require explicit verified migration')
        for name in ('arc-execution.service', 'arc-consensus.service', 'arc-snapshots.service',
                     'erpc-arc-firewall.service'):
            require(not self.protected('/etc/systemd/system/' + name, missing=True).exists() and
                    not self.protected('/etc/systemd/system/' + name + '.d', missing=True, directory=True).exists(),
                    'receipt-free Arc service definitions require explicit verified migration')
        require(not self.protected(custody.CREDENTIAL, missing=True).exists(),
                'receipt-free Arc credential requires explicit verified migration')
        folder = self.protected('/etc/erpc/arc/authority', missing=True, directory=True)
        require(not folder.exists() or set(os.listdir(folder)) <= {'lock', 'owner.json.pending'},
                'unowned Arc authority artifacts cannot be adopted')
        # Account allocation is read-only; no NSS mutation precedes the receipt.
        account = accounts.reserve(self)
        layout = storage.fresh(self)
        probe = self.path(storage.DATA_HOME)
        if not probe.exists():
            probe = probe.parent
        available = os.statvfs(probe)
        require(available.f_bavail * available.f_frsize >= 1000_000_000_000,
                'Arc initial data filesystem needs at least 1 TB available')
        return account, layout

    def prepare(self, wanted, expected_helpers):
        self.platform()
        protocol.contract(wanted)
        if self.protected(OWNER, missing=True).exists():
            state = self.state(wanted)
        else:
            account, layout = self.fresh()
            state = {'schema': SCHEMA, 'contract': wanted, 'machine': self.machine(),
                     **account, 'service_home': storage.DATA_HOME, 'storage': layout,
                     'stopped': ['execution', 'consensus'], 'retired': False,
                     'generation': 0, 'phase': 'prepared'}
            self.save(state)
        # This replay barrier precedes every initial external account mutation.
        self.save(state)
        storage.prepare(self, state)
        source_folder = pathlib.Path(__file__).resolve().parent
        if state.get('helpers') is None:
            state['helpers'] = helpers.publish(self, source_folder, expected_helpers)
            self.save(state)
        else:
            require(state['helpers'] == expected_helpers,
                    'use explicit deployment recovery to upgrade original Arc helpers')
            helpers.publish(self, source_folder, expected_helpers)
        accounts.provision(self, state)
        return {'prepared': True, 'uid': state['service_uid'], 'gid': state['service_gid']}

    def cancel(self, state, layer, retire=False):
        require(layer in ('execution', 'consensus', 'both'), 'invalid Arc layer')
        selected = {'consensus', 'snapshots'} if layer == 'consensus' and not retire else set(process.UNITS)
        state['generation'] += 1
        state['stopped'] = sorted(set(state.get('stopped', [])) | (selected - {'snapshots'}))
        state['phase'] = 'retired' if retire else 'stopped'
        state['retired'] = bool(state.get('retired')) or retire
        state.pop('intent', None)
        failures = []
        # Two independent cancellation publications; either prevents stale activation.
        try:
            self.save(state)
        except Exception:
            failures.append('original Arc cancellation receipt was not synchronized')
        try:
            self.write('/etc/erpc/arc/authority/cancellation.json', {
                'contract': state['contract'], 'generation': state['generation'],
                'stopped': state['stopped'], 'retired': state['retired']})
        except Exception:
            failures.append('Arc cancellation fence was not synchronized')
        try:
            process.stop(self, state, selected, units.historical_runtimes(self, state),
                         lambda component, historical=False: units.proof(self, state, component, historical))
        except Exception:
            failures.append('original Arc shutdown did not complete')
        # Do not rely on active-state or successful persistence before disabling boot.
        for component in selected:
            try:
                units.proof(self, state, component, historical=True)
                result = self.command('/usr/bin/systemctl', 'disable', process.UNITS[component], check=False)
                require(result.returncode == 0, 'Arc boot disable failed')
            except Exception:
                try:
                    absent = process.properties(self, process.UNITS[component])
                    require(absent['LoadState'] == 'not-found' and absent['MainPID'] == '0',
                            'unproven Arc unit remains enabled')
                except Exception:
                    failures.append('Arc boot disable incomplete')
        require(not failures, 'Arc stop or retirement is incomplete; original data and filtering retained')
        return {'applied': 'retired' if retire else 'stopped', 'layer': layer,
                'generation': state['generation'], 'data_preserved': True}

    def cancelled(self, state, component):
        if state.get('retired') or component in state.get('stopped', []):
            return True
        name = '/etc/erpc/arc/authority/cancellation.json'
        if self.protected(name, missing=True).exists():
            fence = self.json(name, private=True)
            require(fence.get('contract') == state['contract'] and type(fence.get('generation')) is int,
                    'Arc cancellation fence differs from the original scope')
            return fence['generation'] >= state['generation'] and (
                fence.get('retired') or component in fence.get('stopped', []))
        return False

    def current_helpers(self, state):
        folder = pathlib.Path(__file__).resolve().parent
        identity = helpers.source(self, folder)[2]
        require(state.get('helpers') == identity, 'Arc executing helper is not the current original release')
        return folder, identity

    def common(self):
        name = '/usr/local/lib/erpc/rpc-firewall.py'
        raw = self.read(name)
        namespace = {'__name__': 'arc_firewall', '__file__': str(self.path(name))}
        exec(compile(raw, str(self.path(name)), 'exec'), namespace)
        def run(argv, **kwargs):
            return self.run(argv, timeout=330, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, **kwargs)
        return namespace['Firewall']('arc', root=self.root, run=run)

    def intent(self, state, token):
        require(isinstance(token, str) and re.fullmatch('[0-9a-f]{32}', token) and
                state.get('intent') == token and state.get('phase') not in ('stopped', 'retired'),
                'Arc deployment was cancelled or superseded')
        return state

    def shutdown(self, state):
        process.stop(self, state, set(process.UNITS), units.historical_runtimes(self, state),
                     lambda component, historical=False: units.proof(self, state, component, historical))

    def reserve(self, state, request):
        require(not state.get('migration_binding') or state.get('migrated') is True,
                'complete the explicit original Arc migration before deployment')
        token = request.get('intent')
        require(isinstance(token, str) and re.fullmatch('[0-9a-f]{32}', token), 'invalid Arc deployment intent')
        target = release.source(request.get('target'))
        policy = protocol.policy(request.get('policy'), state['contract'])
        release.floor(self, state, target)
        # Old queued work loses its generation before a new candidate is acquired.
        self.cancel(state, 'both')
        state['generation'] += 1
        state['intent'], state['target'], state['candidate_policy'] = token, target, policy
        state['phase'], state['retired'] = 'reserved', False
        self.save(state)
        return {'intent': token, 'generation': state['generation']}

    def firewall_prepare(self, state, request):
        self.intent(state, request.get('intent'))
        require(state.get('phase') == 'reserved', 'Arc firewall preparation requires a reserved operation')
        folder = pathlib.Path(__file__).resolve().parent
        identity = helpers.publish(self, folder, request.get('helpers'))
        state['helpers'] = identity
        self.save(state)
        source = folder.parent / 'rpc-firewall.py'
        raw = self.read('/' + str(source.relative_to(self.root)))
        self.write_bytes('/usr/local/lib/erpc/rpc-firewall.py', raw, 0o700)
        boot = ('# Managed original Arc firewall\n[Unit]\nDescription=Arc original boot policy\n'
                'DefaultDependencies=no\nAfter=nftables.service\nBefore=network-pre.target shutdown.target arc-execution.service\n'
                'Wants=network-pre.target\nConflicts=shutdown.target\n'
                'RequiresMountsFor=/opt/erpc /etc/erpc/arc /usr/local/lib/erpc/arc\n'
                '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart='
                + helpers.systemd_command(folder, identity, 'firewall-load', 'firewall')
                + '\n[Install]\nWantedBy=multi-user.target\n')
        self.write_bytes('/etc/systemd/system/erpc-arc-firewall.service', boot.encode(), 0o644)
        self.command('/usr/bin/systemctl', 'daemon-reload')
        return {'prepared': True}

    def firewall_action(self, state, request, action):
        self.intent(state, request.get('intent'))
        common = self.common()
        operation, bundle = request.get('operation'), request.get('bundle')
        common.token(operation, bundle)
        with contextlib.redirect_stdout(io.StringIO()):
            common.dispatch(action, operation, bundle)
        if action == 'confirm':
            state['firewall'] = {'operation': operation, 'bundle': bundle}
            self.save(state)
        return {'firewall': action, 'intent': state['intent']}

    def confirmed(self, state):
        record = state.get('firewall')
        require(isinstance(record, dict) and set(record) == {'operation', 'bundle'},
                'original Arc firewall confirmation is unavailable')
        common = self.common()
        common.require_guards()
        common.require_confirmed(record['operation'], record['bundle'])

    def begin_install(self, state, request):
        self.intent(state, request.get('intent'))
        require(state.get('firewall') == {'operation': request.get('firewall_operation'), 'bundle': request.get('firewall_bundle')},
                'long Arc deployment did not carry the exact confirmed preparation')
        self.confirmed(state)
        accounts.verify(self, state)
        storage.capacity(self, state)
        release.floor(self, state, state['target'])
        state['phase'] = 'installing'
        try:
            self.save(state)
        except Exception:
            try:
                self.shutdown(state)
            finally:
                raise
        self.shutdown(state)
        self.mkdir('/opt/arc/downloads', mode=0o755)
        self.mkdir('/opt/arc/releases', mode=0o755)
        self.protected('/opt/arc/downloads/' + release.identifier(state['target']) + '.tar.gz', missing=True)
        return {'installing': True, 'archive': '/opt/arc/downloads/' + release.identifier(state['target']) + '.tar.gz'}

    def install_native(self, state, request):
        self.intent(state, request.get('intent'))
        require(state['phase'] == 'installing', 'Arc release installation requires a stopped original operation')
        self.confirmed(state)
        accounts.verify(self, state)
        storage.capacity(self, state)
        self.shutdown(state)
        target = state['target']
        release.floor(self, state, target)
        release.install(self, target, '/opt/arc/downloads/' + release.identifier(target) + '.tar.gz')
        folder, identity = self.current_helpers(state)
        texts, runtime = units.make(self, state, target, state['candidate_policy'], folder, identity)
        units.publish(self, state, texts, runtime, target)
        state['policy'] = state['candidate_policy']
        if not state.get('bootstrap_complete') and state.get('bootstrap_pair'):
            state['bootstrap_generation'] = state['generation']
            state['bootstrap_intent'] = state['intent']
            state['phase'] = 'bootstrap-complete'
            self.save(state)
            return {'phase': 'bootstrap-complete', 'started': False}
        if not state.get('bootstrap_complete'):
            bootstrap.prepare(self, state)
            state['phase'] = 'bootstrap'
            state['bootstrap_generation'] = state['generation']
            state['bootstrap_intent'] = state['intent']
            self.save(state)
            self.command('/usr/bin/systemctl', 'start', '--no-block', 'arc-snapshots.service')
            return {'phase': 'bootstrap', 'started': False}
        state['phase'] = 'installed'
        self.save(state)
        return {'phase': 'installed', 'started': False}

    def clock_kernel(self):
        for name, minimum in {'net.core.somaxconn': 4096, 'net.ipv4.tcp_max_syn_backlog': 8192,
                              'vm.max_map_count': 1048576, 'fs.file-max': 4194304}.items():
            result = self.command('/usr/sbin/sysctl', '-n', name)
            require(result.stdout.strip().isdigit() and int(result.stdout.strip()) >= minimum,
                    'Arc kernel operating floor is not established')
        clock = self.command('/usr/bin/timedatectl', 'show', '-p', 'NTPSynchronized', '--value')
        require(clock.stdout.strip() == b'yes', 'Arc requires a synchronized host clock')

    def eligible(self, state, credential=True):
        self.platform()
        self.current_helpers(state)
        accounts.verify(self, state)
        storage.capacity(self, state)
        self.confirmed(state)
        self.clock_kernel()
        release.qualify(self, state['source'])
        release.floor(self, state, state['source'])
        if credential:
            custody.verify(self, state)

    def guard(self, state, component, opening=False):
        require(component in process.UNITS, 'unknown Arc runtime component')
        units.proof(self, state, component)
        self.eligible(state, component == 'consensus')
        if component == 'snapshots':
            require(state['phase'] == 'bootstrap' and not state.get('native_started') and
                    not state.get('bootstrap_complete') and state.get('intent') and
                    state.get('bootstrap_generation') == state['generation'],
                    'Arc bootstrap authorization was cancelled or consumed')
            selected = set(process.UNITS)
        else:
            require(state.get('bootstrap_complete') is True and state.get('phase') in ('starting', 'running', 'stopped') and
                    not self.cancelled(state, component), 'Arc startup is stopped or retired')
            for layer in storage.LAYERS:
                storage.private_directory(self, state, layer, state['directories'][layer])
            selected = {component}
        process.quiescent(self, state, selected, units.historical_runtimes(self, state))
        if component == 'consensus' and opening:
            observe.ipc(self, state)
        if opening:
            release.floor(self, state, state['source'], opening=True)
            if component != 'snapshots':
                state['native_started'] = True
                self.save(state)
        return {'guard': 'original'}

    def start(self, state, layer, restart=False):
        require(layer in ('execution', 'consensus', 'both') and not state.get('retired'),
                'Arc retirement requires explicit deployment before start')
        try:
            self.eligible(state, layer != 'execution' or restart)
            require(state.get('bootstrap_complete'), 'Arc deployment has not completed its original bootstrap')
        except Exception:
            try:
                self.cancel(state, 'both')
            finally:
                raise
        if restart:
            self.cancel(state, 'consensus' if layer == 'consensus' else 'both')
        # Re-render only the stored original source and policy; no stale inventory rollback.
        folder, identity = self.current_helpers(state)
        texts, runtime = units.make(self, state, state['source'], state['policy'], folder, identity)
        for component in process.UNITS:
            units.proof(self, state, component)
        require(all(digest(texts[key].encode()) == state['units'][key] for key in texts),
                'original Arc unit upgrade requires explicit deployment')
        wanted = {'execution'} if layer == 'execution' and not restart else {'execution', 'consensus'}
        if restart and layer == 'consensus':
            wanted = {'consensus'}
            process.running(self, state, 'execution', state['runtime'])
        # Existing active original services are not restarted by start.
        for component in wanted:
            observed = process.properties(self, process.UNITS[component])
            if observed['ActiveState'] == 'active':
                process.running(self, state, component, state['runtime'])
        state['generation'] += 1
        state.pop('intent', None)
        state['stopped'] = sorted(set(state.get('stopped', [])) - wanted)
        state['phase'] = 'starting'
        self.save(state)
        for component in ('execution', 'consensus'):
            if component in wanted:
                self.command('/usr/bin/systemctl', 'enable', process.UNITS[component])
                self.command('/usr/bin/systemctl', 'start', '--no-block', process.UNITS[component])
        return {'startup_requested': True, 'layer': layer, 'ready': None}

    def activate(self, state, request):
        self.intent(state, request.get('intent'))
        if state.get('phase') in ('bootstrap-complete', 'promoting'):
            self.shutdown(state)
            bootstrap.promote(self, state)
        require(state.get('phase') == 'installed', 'Arc installation is incomplete')
        state['retired'] = False
        self.save(state)
        return self.start(state, 'both')

    @contextlib.contextmanager
    def lock(self, blocking=False):
        self.namespaces()
        self.mkdir('/etc/erpc/arc/authority')
        path = self.protected('/etc/erpc/arc/authority/lock', missing=True)
        flags = os.O_RDONLY if path.exists() else os.O_RDWR | os.O_CREAT | os.O_EXCL
        fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == self.owner and info.st_nlink == 1
                    and not info.st_mode & 0o077, 'unsafe Arc authority lock')
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            yield
        finally:
            os.close(fd)

    def dispatch(self, request):
        require(isinstance(request, dict) and request.get('schema') == SCHEMA,
                'invalid Arc authority request')
        action = request.get('action')
        if action == 'preflight':
            require(set(request) in ({'schema', 'action'}, {'schema', 'action', 'contract'}), 'unexpected Arc preflight fields')
            self.platform()
            if 'contract' in request and self.protected(OWNER, missing=True).exists():
                state = self.state(request['contract'])
                accounts.verify(self, state, missing=not state.get('account_established'))
                return {'original': True}
            self.fresh()
            return {'fresh': True}
        wanted = request.get('contract')
        protocol.contract(wanted)
        if action == 'status':
            require(set(request) == {'schema', 'action', 'contract'}, 'unexpected Arc status fields')
            state = self.state(wanted)
            report = observe.report(self, state)
            require(self.state(wanted) == state, 'Arc authority changed during the read-only observation')
            return report
        with self.lock():
            if action in ('migration-check', 'migrate'):
                require(set(request) == {'schema', 'action', 'contract', 'target', 'policy', 'evidence', 'helpers'}, 'unexpected Arc migration fields')
                return migration.check(self, request) if action == 'migration-check' else migration.migrate(self, request)
            if action == 'prepare':
                require(set(request) == {'schema', 'action', 'contract', 'helpers'}, 'unexpected Arc prepare fields')
                return self.prepare(wanted, request['helpers'])
            state = self.state(wanted)
            if action == 'reserve':
                require(set(request) == {'schema', 'action', 'contract', 'intent', 'target', 'policy'}, 'unexpected Arc reserve fields')
                return self.reserve(state, request)
            if action == 'firewall-prepare':
                require(set(request) == {'schema', 'action', 'contract', 'intent', 'helpers'}, 'unexpected Arc firewall preparation fields')
                return self.firewall_prepare(state, request)
            if action in ('firewall-apply', 'firewall-confirm'):
                require(set(request) == {'schema', 'action', 'contract', 'intent', 'operation', 'bundle'}, 'unexpected Arc firewall fields')
                return self.firewall_action(state, request, 'apply' if action == 'firewall-apply' else 'confirm')
            if action in ('begin-install', 'install', 'activate'):
                expected = {'schema', 'action', 'contract', 'intent'}
                if action == 'begin-install':
                    expected |= {'firewall_operation', 'firewall_bundle'}
                require(set(request) == expected, 'unexpected Arc deployment fields')
                return {'begin-install': self.begin_install, 'install': self.install_native, 'activate': self.activate}[action](state, request)
            if action in ('start', 'restart'):
                require(set(request) == {'schema', 'action', 'contract', 'layer'}, 'unexpected Arc service fields')
                return self.start(state, request['layer'], action == 'restart')
            if action in ('stop', 'destroy'):
                require(set(request) == {'schema', 'action', 'contract', 'layer'}, 'unexpected Arc shutdown fields')
                return self.cancel(state, request['layer'], action == 'destroy')
            if action == 'reset-bootstrap':
                require(set(request) == {'schema', 'action', 'contract', 'intent'}, 'unexpected Arc reset fields')
                require(not state.get('native_started') and not state.get('bootstrap_complete') and
                        not state.get('promotion_started') and state.get('bootstrap_intent') == request['intent'],
                        'only the explicit incomplete initial Arc bootstrap may be reset')
                self.cancel(state, 'both')
                return bootstrap.reset(self, state, request['intent'])
            if action == 'credential-restore':
                require(set(request) == {'schema', 'action', 'contract', 'key'}, 'unexpected Arc restore fields')
                accounts.verify(self, state)
                require(custody.public(self, encoded(request['key'])) == state['contract']['public_key'],
                        'restore is not the original Arc key')
                self.cancel(state, 'both')
                return custody.restore_original(self, state, encoded(request['key']))
            if action == 'credential-import':
                require(set(request) == {'schema', 'action', 'contract', 'key'}, 'unexpected Arc custody fields')
                accounts.verify(self, state)
                return custody.import_original(self, state, encoded(request['key']))
            if action == 'credential-recover':
                require(set(request) == {'schema', 'action', 'contract'}, 'unexpected Arc custody fields')
                accounts.verify(self, state)
                return custody.materialize(self, state)
            raise Refused('unsupported Arc authority action')


def main():
    os.umask(0o077)
    try:
        if len(sys.argv) == 3 and sys.argv[1] in ('condition', 'guard', 'snapshot-complete', 'firewall-load'):
            c = Control()
            wanted = c.json(OWNER, private=True)['contract']
            if sys.argv[1] == 'firewall-load':
                c.state(wanted)
                c.common().dispatch('load')
                return 0
            with c.lock(blocking=True):
                state = c.state(wanted)
                if sys.argv[1] == 'snapshot-complete':
                    units.proof(c, state, 'snapshots')
                    c.current_helpers(state)
                    accounts.verify(c, state)
                    process.quiescent(c, state, set(process.UNITS), units.historical_runtimes(c, state))
                    bootstrap.completed(c, state)
                else:
                    c.guard(state, sys.argv[2], sys.argv[1] == 'guard')
            return 0
        raw = sys.stdin.buffer.read(65537)
        require(len(raw) <= 65536, 'Arc request exceeds its bound')
        result = Control().dispatch(strict_json(raw))
        sys.stdout.write(encoded(result).decode() + '\n')
        return 0
    except Refused as error:
        # Only this helper's fixed refusal strings are public, never provider diagnostics.
        sys.stderr.write(str(error) + '\n')
        return 1
    except Exception:
        # Private request bodies and provider/tool diagnostics never enter errors.
        sys.stderr.write('Arc original authority refused the requested operation\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

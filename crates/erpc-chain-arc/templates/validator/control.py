#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original Arc host operations; production signing remains an explicit prerequisite."""
import contextlib
import fcntl
import http.client
import io
import os
from pathlib import Path
import resource
import stat
import sys

from arc_files import Refused, encoded, require, strict_json
from av_files import Files, HOME, ROOT
import arc_release
import av_accounts
import av_events
import av_admission
import av_bootstrap
import av_custody
import av_helpers
import av_ipc
import av_namespace
import av_observe
import av_policy
import av_process
import av_remote
import av_state
import av_storage
import av_units

SOURCE = Path(__file__).absolute().parent


class Controller(Files):
    def preflight_fresh_namespace(self, pending_owner=False):
        av_namespace.check(self, fresh=True, pending_owner=pending_owner)

    def validate_target(self, target):
        arc_release.executable(target)

    def validate_policy(self, state, policy):
        av_policy.validate(state, policy)
        require(policy['phase'] == 'observer',
                'production Arc signing history protection needs provider qualification; activation is unavailable')

    def runtimes(self, state):
        return av_units.historical_runtimes(self, state)

    def unit_proof(self, state, component, historical=False):
        if component == 'firewall':
            return av_units.firewall_proof(self, state)
        return av_units.proof(self, state, component, historical)

    def assert_all_quiescent(self, state):
        av_process.quiescent(self, state, set(av_process.UNITS), self.runtimes(state))

    def assert_consensus_quiescent(self, state):
        av_process.quiescent(self, state, {'consensus'}, self.runtimes(state))

    def assert_bootstrap_finished(self, state):
        self.unit_proof(state, 'bootstrap')
        value = av_process.properties(self, av_process.UNITS['bootstrap'])
        require(value['MainPID'] == '0' and value.get('ExecMainStatus') == '0' and
                value['ActiveState'] in ('activating', 'inactive') and
                value.get('SubState') in ('start-post', 'dead', 'exited'),
                'original native snapshot command has not completed successfully')
        require(not av_process.candidates(self, state), 'snapshot or native writers remain before completion')

    def assert_native_start(self, state, component):
        runtimes = self.runtimes(state)
        for observed in av_process.candidates(self, state):
            role = av_process.classify(self, state, observed, runtimes)
            require(role != component and role != 'bootstrap' and component != 'bootstrap',
                    'original native writer remains before startup')
        value = av_process.properties(self, av_process.UNITS[component])
        require(value['MainPID'] == '0' and value['ActiveState'] in ('inactive', 'activating'),
                'native start is not in its original pre-execution phase')

    def stop_original(self, state):
        av_process.stop(self, state, set(av_process.UNITS), self.runtimes(state))

    def disable_original(self, state):
        failures = []
        for component, unit in av_process.UNITS.items():
            try:
                value = av_process.properties(self, unit)
                if value['LoadState'] == 'not-found':
                    continue
                self.unit_proof(state, component, historical=True)
                result = self.command('/usr/bin/systemctl', 'disable', unit, check=False)
                require(result.returncode == 0, 'original validator unit could not be disabled')
            except Exception:
                failures.append(component)
        require(not failures, 'original Arc validator unit disable was incomplete')

    def is_retired(self):
        state = self.json(av_state.OWNER, private=True)
        return av_state.retired(self, state)

    def is_cancelled(self):
        return self.protected(av_state.HALT, missing=True).exists() or bool(av_events.pending(self))

    def operation_cancelled(self, state):
        if av_events.pending(self):
            return True
        if self.is_retired():
            return True
        if self.is_cancelled():
            fence = self.json(av_state.HALT, private=True)
            if fence.get('intent') is None or (state.get('generation') is not None and
                                               fence.get('intent') != state['generation']):
                return True
        if self.protected(av_state.OPERATION, missing=True).exists():
            operation = self.json(av_state.OPERATION, private=True)
            return operation.get('cancelled') is True or operation.get('history') != av_events.basis(self)
        return False

    def assert_cancelled(self, _state):
        require(not av_events.pending(self) and self.is_cancelled() and self.json(av_state.HALT, private=True).get('intent') is None,
                'explicitly cancelled original Arc services are required')

    def consensus_home(self, state):
        home = av_storage.verify(self, state)
        av_storage.private_directory(self, state, 'consensus', state['directories']['consensus'])
        return home / 'consensus'

    def execution_call(self, state, method, params):
        return av_ipc.call(self, state, method, params)

    def verify_original(self, state):
        av_namespace.check(self)
        av_accounts.verify(state['accounts'])
        self.unit_proof(state, 'firewall')
        for component in ('execution', 'consensus'):
            av_units.proof(self, state, component)
        av_storage.verify(self, state)
        av_custody.verified(self, state)
        av_remote.ca(self, state)
        arc_release.qualify(self, state['source'])
        arc_release.floor(self, state, state['source'])

    def private_response(self, state, path):
        require(path in ('/version', '/status', '/network-state', '/ready'), 'unsupported private Arc observation')
        before = av_process.running(self, state, 'consensus', state['runtime'])
        # Readiness observations are not signing authorization. Admission uses
        # original-EL SO_PEERCRED-bound IPC; this private REST endpoint has no key.
        connection = http.client.HTTPConnection('127.0.0.1', 31000, timeout=10)
        try:
            connection.request('GET', path, headers={'Accept': 'application/vnd.arc.v1+json'})
            response = connection.getresponse()
            raw = response.read(1024 * 1024 + 1)
            require(len(raw) <= 1024 * 1024, 'private Arc observation exceeds its bound')
            require(av_process.running(self, state, 'consensus', state['runtime']) == before,
                    'original consensus changed during private observation')
            return response.status, raw
        finally:
            connection.close()

    def private_rest(self, state, path):
        status, raw = self.private_response(state, path)
        require(status == 200, 'native private observation is unavailable')
        return strict_json(raw)

    def private_ready(self, state):
        status, _ = self.private_response(state, '/ready')
        require(status in (200, 503), 'native readiness probe is unavailable')
        return status == 200

    def firewall_guard_config(self):
        name = '/usr/local/lib/erpc/rpc-firewall.py'
        raw = self.read(name, limit=1048576)
        scope = {'__name__': 'arc_validator_firewall', '__file__': str(self.path(name))}
        exec(compile(raw, str(self.path(name)), 'exec'), scope)
        return scope['Firewall']('arc-validator').guard_config()

    def firewall(self, action, operation=None, bundle=None):
        require(action in ('guard', 'load', 'require-confirmed', 'apply', 'confirm'),
                'unsupported validator ingress operation')
        name = '/usr/local/lib/erpc/rpc-firewall.py'
        raw = self.read(name, limit=1048576)
        scope = {'__name__': 'arc_validator_firewall', '__file__': str(self.path(name))}
        exec(compile(raw, str(self.path(name)), 'exec'), scope)
        with contextlib.redirect_stdout(io.StringIO()):
            scope['Firewall']('arc-validator').dispatch(action, operation, bundle)

    def confirmed_ingress(self, state):
        receipt = state.get('firewall')
        require(isinstance(receipt, dict) and set(receipt) == {'run', 'bundle'},
                'original confirmed validator ingress receipt is missing')
        self.firewall('require-confirmed', receipt['run'], receipt['bundle'])


@contextlib.contextmanager
def operation_lock(context, blocking=False):
    av_namespace.check(context)
    context.mkdir(ROOT)
    path = context.protected(ROOT + '/lock', missing=True)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == context.owner and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600, 'unsafe Arc validator operation lock')
        fcntl.flock(descriptor, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        yield
    finally:
        os.close(descriptor)


def original(context, expected):
    av_namespace.check(context)
    return av_state.original(context, expected)


def observer_start(context, state, intent=None):
    require(state.get('policy', {}).get('phase') == 'observer' and not state.get('signer_used'),
            'production signer activation is not qualified; used history cannot fall back to observer')
    context.verify_original(state)
    context.assert_all_quiescent(state)
    context.confirmed_ingress(state)
    require(state.get('bootstrap_complete') is True and not context.is_retired(),
            'original observer bootstrap is not complete or was retired')
    if intent is not None:
        av_events.runtime(context, state)
        av_state.ready_to_activate(context, state, intent)
    else:
        require(state['phase'] in ('installed', 'running', 'starting') and not state.get('installing'),
                'finish the original Arc deployment before manual start')
        require(not av_events.needs_recovery(context, state), 'pending cancellation needs a fresh explicit deploy')
        if context.is_cancelled():
            require(context.json(av_state.HALT, private=True).get('reason') == 'stopped',
                    'retired or failed deployment requires a fresh explicit deploy')
        else:
            av_events.runtime(context, state)
        av_events.append(context, 'manual', encoded({'owner': state['contract']['owner']}))
        state['authorization_history'] = av_events.basis(context, durable=True)
    try:
        state['phase'] = 'starting'
        state['native_started'] = True
        context.save(state)
        context.remove(av_state.HALT)
        result = context.command('/usr/bin/systemctl', 'enable', '--now', '--no-block',
                                 av_process.UNITS['consensus'], check=False)
        require(result.returncode == 0, 'Arc observer startup request failed')
    except Exception:
        av_state.cancel_and_stop(context, state)
        raise
    return {'startup_requested': True, 'ready': False, 'validator_ready': False,
            'production_signing_history': 'provider-qualification-required'}


def dispatch(context, value, folder=SOURCE):
    require(isinstance(value, dict) and isinstance(value.get('action'), str), 'invalid Arc validator request')
    if value['action'] == 'preflight':
        require(set(value) in ({'action'}, {'action', 'contract'}), 'invalid validator preflight fields')
        if 'contract' in value and context.protected(av_state.OWNER, missing=True).exists():
            state = original(context, value['contract'])
            av_accounts.verify(state['accounts'], missing=not state['accounts']['established'])
            return {'original': True}
        av_namespace.check(context, fresh=True)
        av_storage.fresh(context)
        av_accounts.reserve()
        return {'fresh': True, 'activation_authorized': False}
    fields = {
        'reserve': {'remote_signer', 'ca'}, 'status': set(), 'remote-public-key': {'remote_signer'}, 'custody-status': set(),
        'admission': set(), 'validate-registration': {'registration'}, 'stop': set(), 'destroy': set(), 'provision': set(),
        'publish-helpers': {'helper_hash'},
        'import-peer-key': {'key'}, 'restore-peer-key': {'key'},
        'authorize': {'target', 'policy', 'intent'}, 'begin': {'intent'},
        'install': {'intent', 'helper_hash'},
        'prepare-firewall': {'intent', 'helper_hash'},
        'apply-firewall': {'intent', 'firewall_run', 'firewall_bundle'},
        'confirm-firewall': {'intent', 'firewall_run', 'firewall_bundle'},
        'require-firewall': {'intent', 'firewall_run', 'firewall_bundle'},
        'bootstrap': {'intent'}, 'promote': {'intent'}, 'reset-bootstrap': {'bootstrap_intent'},
        'activate': {'intent'}, 'start': set(),
    }
    action = value['action']
    require(action in fields and set(value) == {'action', 'contract'} | fields[action],
            'unknown or missing Arc validator request field')
    av_state.contract(value['contract'])
    if action == 'reserve':
        require(isinstance(value['ca'], str), 'invalid operator remote signer CA')
        raw = av_remote.certificate(value['ca'].encode('ascii'), value['remote_signer'])
        state = av_state.reserve(context, value['contract'])
        old = state.get('remote_signer')
        require(old is None or old == value['remote_signer'], 'original remote signer qualification cannot be replaced')
        if old is None:
            state['remote_signer'] = value['remote_signer']
            context.save(state)
        if context.protected(av_remote.CA, missing=True).exists():
            require(context.read(av_remote.CA, private=True) == raw, 'original remote signer CA cannot be overwritten')
        context.write_bytes(av_remote.CA, raw)
        av_remote.ca(context, state)
        return {'reserved': True, 'peer_public_key': state['contract']['peer_public_key'],
                'consensus_public_key': state['contract']['public_key'], 'activation_authorized': False}
    state = original(context, value['contract'])
    if action == 'status':
        return av_observe.status(context, state)
    if action == 'custody-status':
        if state.get('credential') is None:
            require(not context.protected(av_custody.CREDENTIAL, missing=True).exists(),
                    'receipt-free peer ciphertext cannot be adopted')
            return {'present': False}
        av_custody.verified(context, state, prove=True)
        return {'present': True, 'public_key': state['contract']['peer_public_key']}
    if action == 'remote-public-key':
        require(av_remote.inputs(value['remote_signer']) == state.get('remote_signer'),
                'caller remote signer qualification differs from the original host receipt')
        return av_remote.public_key(context, state)
    if action == 'admission':
        return av_admission.observe(context, state)
    if action == 'validate-registration':
        return av_admission.simulate(context, state, value['registration'])
    if action == 'stop' or action == 'destroy':
        return av_state.cancel_and_stop(context, state, retire=action == 'destroy')
    if action == 'provision':
        av_accounts.provision(context, state)
        av_storage.prepare(context, state)
        context.mkdir('/opt/arc', mode=0o755)
        context.mkdir('/opt/arc/downloads')
        context.mkdir('/opt/arc/releases', mode=0o755)
        for native_parent in ('/opt', '/opt/arc', '/opt/arc/releases'):
            require(context.protected(native_parent, directory=True).stat().st_mode & 0o005 == 0o005,
                    'original native public artifact ancestors are not traversable')
        return {'prepared': True, 'activation_authorized': False}
    if action == 'publish-helpers':
        av_accounts.verify(state['accounts'])
        av_storage.verify(context, state)
        state['helper_hash'] = av_helpers.publish(context, folder, value['helper_hash'])
        context.save(state)
        return {'helpers': 'original', 'activation_authorized': False}
    if action in ('import-peer-key', 'restore-peer-key'):
        raw = value['key'].encode('ascii')
        function = av_custody.import_original if action == 'import-peer-key' else av_custody.restore_original
        return function(context, state, raw)
    if action == 'authorize':
        arc_release.floor(context, state, value['target'])
        return av_state.authorize(context, state, value['intent'], value['target'], value['policy'])
    if action == 'begin':
        context.confirmed_ingress(state)
        result = av_state.begin(context, state, value['intent'])
        av_storage.capacity(context, state)
        return dict(result, archive='/opt/arc/downloads/' + arc_release.identifier(state['target']) + '.tar.gz')
    if action == 'install':
        av_state.active_operation(context, state, value['intent'])
        context.confirmed_ingress(state)
        require(state['phase'] == 'installing' and state['generation'] == value['intent'],
                'original installation intent differs')
        context.assert_all_quiescent(state)
        arc_release.floor(context, state, state['target'])
        native = state['target']
        arc_release.install(context, native, '/opt/arc/downloads/' + arc_release.identifier(native) + '.tar.gz')
        helper_hash = av_helpers.publish(context, folder, value['helper_hash'])
        units, runtime = av_units.make(context, state, native, state['policy'], folder, helper_hash)
        av_units.publish(context, state, units, runtime, native)
        state['helper_hash'] = helper_hash
        if state.get('bootstrap_complete'):
            state['phase'] = 'installed'
        context.save(state)
        return {'native_installed': True, 'activation_authorized': False}
    if action == 'prepare-firewall':
        av_state.active_operation(context, state, value['intent'], allow_retired=True)
        helper_hash = av_helpers.publish(context, folder, value['helper_hash'])
        state['helper_hash'] = helper_hash
        context.save(state)
        common = folder.parent / 'rpc-firewall.py'
        common_path = '/' + str(common.relative_to(context.root))
        context.write_bytes('/usr/local/lib/erpc/rpc-firewall.py', context.read(common_path), 0o700)
        unit = ('# Managed Arc validator preparation firewall\n[Unit]\n'
                'Description=Arc validator original ingress\nDefaultDependencies=no\n'
                'After=nftables.service\nBefore=network-pre.target shutdown.target\n'
                'Wants=network-pre.target\nConflicts=shutdown.target\n'
                'RequiresMountsFor=/opt/erpc /etc/erpc/arc-validator /usr/local/lib/erpc/arc-validator\n'
                '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart='
                + av_helpers.systemd_command(folder, helper_hash, 'firewall-load', 'firewall')
                + '\n[Install]\nWantedBy=multi-user.target\n')
        av_units.publish_firewall(context, state, unit)
        context.command('/usr/bin/systemctl', 'daemon-reload')
        return {'ingress': 'prepared', 'intent': value['intent']}
    if action in ('apply-firewall', 'confirm-firewall'):
        av_state.active_operation(context, state, value['intent'], allow_retired=True)
        require(context.json(av_state.HALT, private=True) ==
                {'intent': value['intent'], 'reason': 'new-deployment'},
                'validator ingress preparation was explicitly cancelled')
        context.firewall('apply' if action == 'apply-firewall' else 'confirm',
                         value['firewall_run'], value['firewall_bundle'])
        return {'ingress': 'applied' if action == 'apply-firewall' else 'confirmed',
                'intent': value['intent']}
    if action == 'require-firewall':
        av_state.active_operation(context, state, value['intent'], allow_retired=True)
        context.firewall('require-confirmed', value['firewall_run'], value['firewall_bundle'])
        state['firewall'] = {'run': value['firewall_run'], 'bundle': value['firewall_bundle']}
        context.save(state)
        return {'ingress': 'confirmed'}
    if action == 'bootstrap':
        av_state.active_operation(context, state, value['intent'])
        context.confirmed_ingress(state)
        require(state.get('generation') == value['intent'], 'original bootstrap generation differs')
        if state.get('bootstrap_complete'):
            return {'bootstrap': 'original-complete'}
        if state.get('bootstrap_pair'):
            context.assert_all_quiescent(state)
            state['bootstrap_generation'] = value['intent']
            state['phase'] = 'promoting' if state.get('promotion_started') else 'bootstrap-complete'
            context.save(state)
            return {'bootstrap': 'original-pair-retained'}
        previous = state.get('bootstrap_intent')
        retained = state.get('retained_bootstrap', {})
        require(previous is None or (retained.get('intent') == previous and
                'bootstrap' not in state.get('directories', {}) and
                'bootstrap' not in state.get('directory_intents', {})),
                'incomplete original bootstrap requires explicit stop and reset-bootstrap before a fresh attempt')
        av_bootstrap.prepare(context, state)
        state['bootstrap_intent'] = value['intent']
        state['bootstrap_generation'] = value['intent']
        state['phase'] = 'bootstrap'
        context.save(state)
        context.unit_proof(state, 'firewall')
        context.unit_proof(state, 'bootstrap')
        context.command('/usr/bin/systemctl', 'start', '--no-block', av_process.UNITS['bootstrap'])
        return {'bootstrap': 'requested'}
    if action == 'promote':
        av_state.active_operation(context, state, value['intent'])
        context.confirmed_ingress(state)
        return av_bootstrap.promote(context, state)
    if action == 'reset-bootstrap':
        return av_bootstrap.reset(context, state, value['bootstrap_intent'])
    if action == 'activate':
        return observer_start(context, state, value['intent'])
    if action == 'start':
        return observer_start(context, state)
    raise Refused('unsupported Arc validator host operation')


def boot(context, action, component):
    require(action in ('condition', 'guard', 'bootstrap-complete', 'firewall-load') and
            component in (*av_process.UNITS, 'firewall'), 'unknown native Arc validator entrypoint')
    av_namespace.check(context)
    state = context.json(av_state.OWNER, private=True)
    state = av_state.original(context, state['contract'])
    require(state.get('helper_hash') == av_helpers.source(context, SOURCE)[2],
            'native unit selected another helper generation')
    if action == 'firewall-load':
        require(component == 'firewall', 'wrong ingress entrypoint')
        context.unit_proof(state, 'firewall')
        context.firewall('load')
        return {'ingress': 'loaded'}
    require(component in av_process.UNITS, 'unknown native component')
    av_accounts.verify(state['accounts'])
    context.unit_proof(state, component)
    av_events.runtime(context, state)
    require(not context.is_retired(), 'original Arc validator was retired')
    if component == 'bootstrap':
        av_state.active_operation(context, state, state['bootstrap_generation'])
        require(state['phase'] == 'bootstrap' and not state.get('signer_used') and
                context.json(av_state.HALT, private=True) ==
                {'intent': state['bootstrap_generation'], 'reason': 'new-deployment'},
                'native bootstrap was cancelled or superseded')
    else:
        require(state['phase'] in ('starting', 'running') and not context.is_cancelled() and
                state['policy']['phase'] == 'observer' and not state.get('signer_used'),
                'original observer startup is not authorized; production signer activation remains unqualified')
        context.firewall('guard')
    if action in ('condition', 'guard'):
        context.assert_native_start(state, component)
        if component == 'consensus':
            av_custody.verified(context, state)
    if action == 'condition':
        return {'original_account': 'verified', 'original_credential': component == 'consensus'}
    if action == 'bootstrap-complete':
        require(component == 'bootstrap', 'wrong native completion component')
        return av_bootstrap.completed(context, state)
    av_storage.capacity(context, state)
    arc_release.qualify(context, state['source'])
    if component == 'consensus':
        av_custody.verified(context, state, prove=True)
        av_ipc.namespace(context, state)
        av_process.running(context, state, 'execution', state['runtime'])
    arc_release.floor(context, state, state['source'], opening=True)
    return {'original_native_source': 'authorized'}


def main():
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.environ.clear()
    os.environ.update({'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(os.geteuid() == 0 and sys.flags.isolated, 'isolated root Arc validator controller required')
    context = Controller()
    if len(sys.argv) == 3:
        with operation_lock(context, blocking=True):
            result = boot(context, sys.argv[1], sys.argv[2])
        print(encoded(result).decode())
        return
    require(sys.argv[1:] == [], 'unsupported Arc validator controller arguments')
    raw = sys.stdin.buffer.read(262145)
    require(0 < len(raw) <= 262144, 'invalid bounded Arc validator request')
    value = strict_json(raw)
    with operation_lock(context):
        result = dispatch(context, value)
    print(encoded(result).decode())


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Arc validator operation refused; original authority and provider diagnostics retained', file=sys.stderr)
        raise SystemExit(1) from None

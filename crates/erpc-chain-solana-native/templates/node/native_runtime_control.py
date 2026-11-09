# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fixed runtime entrypoint, reached only through the external protected loader."""
import fcntl
import hashlib
import os
from pathlib import Path
import resource
import stat
import subprocess
import sys
from native_files import Refused, json_value, read, require, root_directory
from native_contract import validate
from native_state import State, token
import native_accounts as accounts
import native_custody as custody
import native_host as host
import native_publish as publish
import native_runtime_observer as observer
import native_runtime_process as process
import native_runtime_unit as units
import native_tuning as tuning
import native_helpers as helpers
import native_source_floor as source_floor
import native_migration_settings as migration_settings

STATE = Path('/var/lib/erpc-solana/state')
OPERATION_ROOT = Path('/opt/erpc')
LOCK = Path('/run/lock/erpc-solana-native.lock')


def load():
    root_directory(STATE)
    state = State(STATE)
    contract = validate(state.get('owner.json')['contract'])
    state.owner(contract)
    return state, contract


def selected(contract, active):
    """Bind the approved runtime to one published build and immutable helper set."""
    receipt = active['receipt']
    fields = {'build', 'mode', 'identity', 'helper_revision', 'cipher_sha256', 'unit_sha256', 'firewall', 'account'}
    require(isinstance(receipt, dict) and set(receipt) - {'migration'} in (fields, fields | {'gateway'}, fields | {'validator'}),
        'native runtime receipt fields differ')
    require(('validator' in receipt) == (receipt['mode'] == 'validator'),
            'voting runtime must retain its original registration and native BLS proof')
    revision = receipt['helper_revision']
    require(isinstance(revision, str) and len(revision) == 64
            and all(c in '0123456789abcdef' for c in revision), 'invalid native helper revision')
    directory = units.HELPERS / revision
    root_directory(directory)
    require(helpers.verify(revision) == directory, 'native helper namespace differs')
    raw = read(directory / 'catalog.json', 65536)
    catalog = json_value(raw)
    profile = catalog['networks'][contract['network']]
    build = receipt['build']; request = build['request']
    require(request['network'] == contract['network'] and request['version'] == profile['version']
            and request['commit'] == profile['commit']
            and request['catalog_sha256'] == hashlib.sha256(raw).hexdigest()
            and build['source'] == {key: profile[key] for key in ('commit', 'cargo_lock_sha256', 'rust')},
            'native published build differs from the selected source catalog')
    token(request['intent'])
    target = active['target']
    require(all(target[key] == request[key] for key in ('network', 'version', 'commit', 'catalog_sha256'))
            and target.get('build_intent', request['intent']) == request['intent']
            and target['mode'] == receipt['mode'] and target['identity'] == receipt['identity'],
            'native active request differs from the approved runtime')
    argv = units.arguments(contract, catalog, request['intent'], receipt['mode'], receipt['identity'], receipt.get('migration'))
    definition = units.render(contract, catalog, request['intent'], revision, receipt['mode'], receipt['identity'], receipt['account'], receipt.get('migration'))
    require(hashlib.sha256(definition.encode()).hexdigest() == receipt['unit_sha256'],
            'native runtime definition differs from its immutable receipt')
    return receipt, profile, argv, definition


def unit_definition(expected):
    root_directory(units.UNITS)
    require(read(units.UNITS / units.UNIT) == expected.encode(), 'native runtime service definition changed')
    directory = units.UNITS / (units.UNIT + '.d')
    if directory.exists() or directory.is_symlink():
        root_directory(directory)
        require(all(p.name in ('50-erpc-firewall-guard.conf', '50-erpc-firewall-guard.conf.new')
                    for p in directory.iterdir()), 'native runtime has an unknown service override')
        for path in directory.iterdir(): read(path)


def systemctl(args, allowed=(0,), timeout=60):
    result = subprocess.run(['/usr/bin/systemctl', *args], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'})
    require(result.returncode in allowed and len(result.stdout) <= 65536,
            'native service operation failed; inspect its journal')
    return result.stdout.decode('utf-8')


def service(account, run=systemctl):
    raw = run(['show', units.UNIT,
        '--property=LoadState,ActiveState,SubState,MainPID,FragmentPath,DropInPaths,User,Group,NeedDaemonReload'])
    values = {}
    for line in raw.splitlines():
        key, separator, value = line.partition('=')
        require(separator and key not in values, 'ambiguous native service metadata')
        values[key] = value
    require(values.get('LoadState') == 'loaded'
            and values.get('FragmentPath') == str(units.UNITS / units.UNIT)
            and values.get('DropInPaths') in ('', str(units.UNITS / (units.UNIT + '.d/50-erpc-firewall-guard.conf')))
            and values.get('User') == str(account['uid']) and values.get('Group') == str(account['gid'])
            and values.get('NeedDaemonReload') == 'no', 'native loaded service authority differs')
    pid = values.get('MainPID', '')
    require(pid.isdecimal(), 'invalid native service process identity')
    values['MainPID'] = int(pid)
    return values


def firewall(receipt):
    import native_firewall
    state, contract = load()
    manager = native_firewall.installed(state, contract)
    value = receipt['firewall']
    require(isinstance(value, dict) and set(value) == {'run', 'bundle'}, 'native ingress receipt differs')
    manager.dispatch('require-confirmed', value['run'], value['bundle'])


def qualify(state, contract, active):
    migration = migration_settings.load(state, contract)
    require(active['receipt'].get('migration') == migration, 'runtime omitted or changed the original migration policy')
    if migration is not None: migration_settings.verify(migration)
    receipt, profile, argv, definition = selected(contract, active)
    unit_definition(definition)
    identities = accounts.verify(state, contract)
    require(receipt['account'] == {key: identities['node'][key] for key in ('uid', 'gid')},
            'native credential recipient differs from the original account')
    host.capacity(state, contract)
    tuning.verify(state, contract)
    node = identities['node']
    for mount in units.MOUNTS.values():
        info = (mount / 'data').lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == node['uid']
                and info.st_gid == node['gid'] and info.st_mode & 0o7777 == 0o700,
                'native data directory differs from its isolated account')
    build = receipt['build']
    publish.verify(units.RELEASES / build['request']['intent'], build)
    source_floor.check(state, contract, source_floor.from_profile(profile))
    cipher = units.CUSTODY / (receipt['mode'] + '.cred')
    root_directory(units.CUSTODY)
    require(cipher.lstat().st_mode & 0o7777 == 0o600, 'native credential is not private')
    raw = read(cipher, 1048576)
    require(hashlib.sha256(raw).hexdigest() == receipt['cipher_sha256'], 'native credential differs from approval')
    if receipt['mode'] == 'validator':
        import native_activation
        native_activation.qualify(state, contract, receipt['validator'], profile['genesis'])
    firewall(receipt)
    if contract['profile'] == 'agave-native-rpc':
        import native_gateway
        native_gateway.verify(state, contract, receipt.get('gateway'))
    else:
        require(receipt.get('gateway') is None, 'validator cannot adopt public ingress')
    return receipt, profile, argv, identities


def guard(state, contract, run=systemctl):
    active = state.guard(contract)
    result = qualify(state, contract, active)
    service(result[3]['node'], run)
    # Pre-start runs with '+': full privileges and the real /dev, so mount UUIDs
    # stay visible, but inside the namespace that holds the unit's ReadWritePaths
    # binds; native_mounts reads the host's table from PID 1. No custody is
    # decrypted here.
    process.proc.assert_quiescent(result[3]['node']['uid'])
    source_floor.claim(state, contract, source_floor.from_profile(result[1]))
    require(state.guard(contract) == active, 'native activation changed during startup checks')
    return result


def account_receipt(state, contract):
    state.owner(contract)
    receipt = state.get('accounts.json')
    require(set(receipt) in ({'contract', 'accounts'}, {'contract', 'accounts', 'opening_protocol'})
            and receipt['contract'] == contract
            and ('opening_protocol' not in receipt or type(receipt['opening_protocol']) is int and receipt['opening_protocol'] == 1),
            'native shutdown account ownership differs')
    accounts.validate_plan(receipt['accounts'])
    return receipt['accounts']['node']


def shutdown(state, contract, run=systemctl):
    """Stop the fixed owned service even when custody/mount/NSS checks fail.

    Both the last approved definition and a durably recorded installation
    candidate are recognized. An unknown unit is never signaled or overwritten.
    """
    node = account_receipt(state, contract)
    definitions = []
    for name in ('active.json', 'runtime-install.json'):
        if (state.directory / name).exists():
            digest = state.get(name)['receipt']['unit_sha256']
            require(isinstance(digest, str) and len(digest) == 64
                    and all(c in '0123456789abcdef' for c in digest), 'invalid owned service receipt')
            definitions.append(digest)
    file = units.UNITS / units.UNIT
    root_directory(units.UNITS)
    if file.exists() or file.is_symlink():
        actual = read(file)
        require(hashlib.sha256(actual).hexdigest() in definitions,
                'native shutdown cannot adopt an unknown service')
        unit_definition(actual.decode())
        run(['daemon-reload'])
        service(node, run)
    else:
        load = run(['show', units.UNIT, '--property=LoadState', '--value'], allowed=(0, 1)).strip()
        require(load == 'not-found', 'native service file is missing while its unit remains loaded')
        process.proc.assert_quiescent(node['uid'])
        return
    failures = []
    try: run(['stop', units.UNIT], timeout=1860)
    except Exception: failures.append('shutdown')
    try: run(['disable', units.UNIT])
    except Exception: failures.append('disable')
    try:
        observed = service(node, run)
        require(observed['ActiveState'] in ('inactive', 'failed') and observed['MainPID'] == 0,
                'native runtime remains active')
        process.proc.assert_quiescent(node['uid'])
    except Exception: failures.append('quiescence')
    require(not failures, 'native shutdown or quiescence failed; data and credentials retained')


def shutdown_all(state, contract, run=systemctl):
    import native_deployment
    import native_gateway
    import native_proof
    failures = []
    for stop in (lambda: native_deployment.cancel_builds(state, contract, run),
                 lambda: native_proof.stop(state, contract, run),
                 lambda: native_gateway.shutdown(state, contract, run),
                 lambda: shutdown(state, contract, run)):
        try: stop()
        except Exception: failures.append(True)
    require(not failures, 'native runtime or source-build shutdown failed; data retained')


def dispatch(state, contract, request, run=systemctl):
    if isinstance(request, dict) and request.get('action') == 'authorize-validator':
        import native_activation
        return native_activation.authorize(state, contract, request, run)
    if isinstance(request, dict) and request.get('action') == 'logs':
        base = {'action', 'contract', 'lines'}
        require(set(request) in (base, base | {'component'}, base | {'component', 'intent'}) and request['contract'] == contract
                and type(request['lines']) is int and 1 <= request['lines'] <= 1000,
                'invalid native journal request')
        state.owner(contract)
        component = request.get('component', 'node')
        require(component in ('node', 'gateway', 'firewall', 'build')
                and ('intent' not in request or component == 'build'), 'invalid native journal component')
        selected = [units.UNIT]
        if component == 'gateway':
            require(contract['profile'] == 'agave-native-rpc', 'validator has no public ingress journal')
            selected = ['erpc-solana-gateway.service']
        elif component == 'firewall': selected = ['erpc-solana-native-firewall.service']
        elif component == 'build':
            intent = request.get('intent')
            if intent is None:
                if (state.directory / 'pending.json').exists():
                    pending = state.get('pending.json')
                    intent = pending['target'].get('build_intent', pending['intent'])
                elif (state.directory / 'active.json').exists(): intent = state.get('active.json')['receipt']['build']['request']['intent']
            intent = token(intent)
            authority = state.get('build-authority-' + intent + '.json')
            require(authority['contract'] == contract and authority['intent'] == intent,
                    'build journal lacks its original host authority')
            selected = ['erpc-solana-' + phase + '-' + intent + '.service' for phase in ('fetch', 'compile')]
        result = subprocess.run(['/usr/bin/journalctl', *['--unit=' + unit for unit in selected], '--no-pager',
            '--output=json', '--lines=' + str(request['lines'])], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'})
        require(result.returncode == 0 and len(result.stdout) <= 4 * 1024 * 1024,
                'native journal inspection failed or exceeded its bound')
        entries = [json_value(line) for line in result.stdout.splitlines()]
        require(len(entries) <= request['lines'], 'native journal line bound exceeded')
        return {'units': selected, 'entries': entries}
    if isinstance(request, dict) and request.get('action') == 'prove-validator':
        require(set(request) == {'action', 'contract', 'intent'} and request['contract'] == contract,
                'invalid native validator proof request')
        import native_proof
        return native_proof.derive(state, contract, request['intent'], run)
    if isinstance(request, dict) and request.get('action') in ('begin-runtime', 'install-runtime', 'activate-runtime'):
        import native_deployment
        expected = {'action', 'contract', 'intent'}
        if request['action'] == 'install-runtime': expected.add('firewall')
        require(set(request) == expected and request['contract'] == contract, 'invalid native runtime deployment request')
        if request['action'] == 'begin-runtime':
            return native_deployment.begin_runtime(state, contract, request['intent'], run)
        if request['action'] == 'install-runtime':
            return native_deployment.install_runtime(state, contract, request['intent'], request['firewall'], run)
        return native_deployment.activate_runtime(state, contract, request['intent'], run)
    if isinstance(request, dict) and request.get('action') in ('authorize-build', 'build-phase', 'abandon-build', 'recover-cutover'):
        import native_deployment
        if request['action'] == 'authorize-build':
            return native_deployment.authorize(state, contract, request)
        if request['action'] == 'recover-cutover':
            require(set(request) == {'action', 'contract', 'intent'} and request['contract'] == contract,
                    'invalid explicit native cutover recovery request')
            return native_deployment.recover_cutover(state, contract, request['intent'], run)
        if request['action'] == 'abandon-build':
            require(set(request) == {'action', 'contract', 'intent'} and request['contract'] == contract,
                    'invalid native build cancellation request')
            return native_deployment.abandon(state, contract, request['intent'], run)
        require(set(request) == {'action', 'contract', 'intent', 'phase'} and request['contract'] == contract,
                'invalid native build phase request')
        return native_deployment.step(state, contract, request['intent'], request['phase'])
    if isinstance(request, dict) and request.get('action') == 'import-identity':
        require(set(request) == {'action', 'contract', 'intent', 'role', 'key_file', 'expected', 'restore'}
                and request['contract'] == contract and isinstance(request['key_file'], str),
                'native identity request ownership or format differs')
        receipt = custody.import_identity(state, contract, request['intent'], request['role'],
            request['key_file'].encode(), request['expected'], lambda: shutdown(state, contract, run),
            request['restore'])
        return {'identity': receipt['public'], 'role': receipt['role'], 'custody_verified': True}
    require(isinstance(request, dict) and set(request) == {'action', 'contract'}
            and request['contract'] == contract, 'native operation ownership differs')
    action = request['action']
    if action in ('gateway-package-prepare', 'gateway-package-check'):
        import native_gateway
        return native_gateway.package(state, contract, run, prepare=action == 'gateway-package-prepare')
    if action == 'status': return status(state, contract, run)
    if action == 'opening-authority': return source_floor.observation(state, contract)
    if action == 'deployment':
        state.owner(contract)
        def access(intent):
            name = 'firewall-preparation-' + token(intent) + '.json'
            if not (state.directory / name).exists(): return None
            value = state.get(name)
            require(value['contract'] == contract and value['intent'] == intent,
                    'native ingress preparation belongs to another deployment')
            return value['access']
        value = None
        if (state.directory / 'pending.json').exists():
            value = state.get('pending.json')
            current = False
            try:
                state.current(contract, value['intent'])
                current = True
            except Exception: pass
            value = dict(value, current=current, access=access(value['intent']))
        approved = None
        recovery = None
        if (state.directory / 'cutover-recovery.json').exists():
            record = state.get('cutover-recovery.json')
            require(record['contract'] == contract and record['phase'] in ('prepared', 'complete'),
                    'native cutover recovery metadata differs')
            recovery = {'intent': token(record['intent']), 'phase': record['phase']}
        cutover = (state.directory / 'cutover.json').exists()
        halt = state.halt()
        if (state.directory / 'active.json').exists():
            active = state.get('active.json')
            approved = {'target': active['target'], 'access': access(active['intent']),
                        'authorized': active['halt'] == halt['generation'] and not halt['retired'] and not cutover}
        return {'pending': value, 'approved': approved, 'cutover': cutover, 'retired': halt['retired'], 'recovery': recovery,
                'opening_authority': source_floor.observation(state, contract)}
    if action in ('stop', 'destroy', 'restart'):
        state.stop(contract, lambda: shutdown_all(state, contract, run), retired=action == 'destroy')
        if action != 'restart':
            return {'operation': {'action': action, 'applied': True}, 'data_preserved': True}
    require(action in ('start', 'restart'), 'unsupported native runtime operation')
    try:
        state.manual_start(contract, lambda active: qualify(state, contract, active))
        run(['daemon-reload'])
        node = account_receipt(state, contract)
        service(node, run)
        run(['enable', units.UNIT])
        run(['start', units.UNIT], timeout=210)
        started = service(node, run)
        require(started['ActiveState'] == 'active' and started['SubState'] == 'running'
                and started['MainPID'] > 0, 'native startup condition or service did not start')
        if contract['profile'] == 'agave-native-rpc':
            import native_gateway
            native_gateway.start(state, contract, state.guard(contract)['receipt']['gateway'], run)
    except Exception:
        state.stop(contract, lambda: shutdown_all(state, contract, run))
        raise
    return {'operation': {'action': action, 'applied': True}, 'observation': status(state, contract, run)}


def control(request, carried=False, private_export=False):
    require(isinstance(request, dict), 'invalid native runtime operation')
    require(not private_export or not carried and request.get('action')=='migration-export',
            'private original response requires its dedicated migration action')
    if request.get('action') == 'migration-status':
        import native_migration_retire
        return native_migration_retire.control(request,carried)
    if request.get('action') == 'firewall-confirm':
        import native_firewall
        state, contract = load()
        return native_firewall.confirm(state, contract, request)
    if request.get('action') == 'toolchain':
        require(set(request) == {'action', 'contract', 'intent'}, 'invalid native toolchain request')
        state, contract = load()
        require(request['contract'] == contract, 'native toolchain ownership differs')
        import native_deployment
        return native_deployment.install_toolchain(state, contract, request['intent'])
    if request.get('action') == 'preflight':
        require(set(request) == {'action', 'role', 'network', 'volumes'}, 'invalid native preflight fields')
        import native_host
        return native_host.preflight(request['role'], request['network'], request['volumes'])
    if request.get('action') in ('status', 'deployment', 'logs', 'opening-authority'):
        state, contract = load()
        return dispatch(state, contract, request)
    root_directory(OPERATION_ROOT)
    operation = os.open(OPERATION_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not carried: fcntl.flock(operation, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'r+b') as lock:
            info = os.fstat(lock.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and info.st_mode & 0o7777 == 0o600, 'unsafe native runtime lock')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if private_export:
                require(not carried and request.get('action')=='migration-export','private migration export scope differs')
                import native_migration_retire as retirement
                import native_migration_custody
                public=retirement.scope(request);uid=retirement.management(public['legacy'],False)
                return native_migration_custody.Capture(retirement.Retirement(request,uid)).export()
            if str(request.get('action','')).startswith('migration-'):
                import native_migration_retire
                return native_migration_retire.control(request,carried)
            if request.get('action') == 'prepare':
                require(set(request) == {'action', 'contract'}, 'invalid native preparation fields')
                import native_host
                result = native_host.prepare(request['contract'])
                result['helper_revision'] = helpers.publish()
                State(STATE).put('helper-revision.json', {'revision': result['helper_revision']})
                return result
            if request.get('action') == 'upgrade-source-authority':
                require(carried and set(request) == {'action', 'contract', 'original_client_record'},
                        'source-history upgrade requires its explicit sealed original record')
                state, contract = load()
                require(request['contract'] == contract, 'source-history upgrade belongs to another original host')
                revision = helpers.publish()
                raw = read(units.HELPERS / revision / 'catalog.json', 65536)
                profile = json_value(raw)['networks'][contract['network']]
                result = source_floor.upgrade(state, contract, request['original_client_record'], profile, systemctl)
                state.put('helper-revision.json', {'revision': revision})
                result['helper_revision'] = revision
                return result
            state, contract = load()
            if request.get('action') == 'firewall-prepare':
                require(carried, 'native firewall preparation requires a sealed operation bundle')
                import native_firewall
                return native_firewall.prepare(state, contract, request, host.command)
            return dispatch(state, contract, request)
    finally:
        os.close(operation)


def status(state, contract, run=systemctl):
    result = {'rpc_ready': False, 'validator_ready': False}
    try:
        active = state.guard(contract)
        receipt, profile, argv, identities = qualify(state, contract, active)
        account = identities['node']
        def prove():
            require(state.guard(contract) == active, 'native runtime authorization changed')
            observed = service(account, run)
            require(observed['ActiveState'] == 'active' and observed['SubState'] == 'running',
                    'native service is not running')
            return process.prove(observed['MainPID'], account['uid'], account['gid'], Path(argv[0]), argv)
        result = observer.inspect(profile, receipt['identity'], prove)
        result['validator_ready'] = False
        if receipt['mode'] == 'validator':
            import native_activation
            import native_validator
            original = prove()
            registration, _ = native_activation.approved(state, contract, receipt['validator'])
            participation = native_validator.participation(registration['registration'], profile['genesis'])
            require(prove() == original, 'native voter changed during public participation observation')
            result['participation'] = participation
            result['validator_ready'] = result['rpc_ready'] and participation['validator_ready']
        if contract['profile'] == 'agave-native-rpc':
            import native_gateway_observer
            ingress = native_gateway_observer.inspect(state, contract, active, profile, run)
            result['native_rpc_ready'] = result['rpc_ready']
            result['ingress'] = ingress
            result['rpc_ready'] = result['rpc_ready'] and ingress['rpc_ready']
        result['mode'] = receipt['mode']
    except Exception:
        result['validator_ready'] = False
        result['inspection_error'] = 'native ownership, runtime or synchronization unavailable'
    return result


def main():
    os.umask(0o077); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    require(sys.platform == 'linux' and os.geteuid() == 0, 'native runtime control requires Linux root')
    if len(sys.argv)==3 and sys.argv[1]=='migration-run-condition':
        import native_migration_guard
        native_migration_guard.permit(sys.argv[2]);return
    require(sys.argv[1:] in (['condition'], ['guard'], ['control'], ['play'], ['firewall-load'],
            ['gateway-condition'], ['gateway-guard'], ['proof-condition'], ['proof-guard'], ['migration-export']), 'unsupported native runtime entrypoint')
    if sys.argv[1:] in (['proof-condition'], ['proof-guard']):
        import native_proof
        state, contract = load()
        native_proof.guard(state, contract, systemctl, plaintext=sys.argv[1:] == ['proof-guard'])
        return
    if sys.argv[1:] in (['gateway-condition'], ['gateway-guard']):
        import native_gateway
        state, contract = load()
        native_gateway.guard(state, contract, systemctl)
        return
    if sys.argv[1:] == ['firewall-load']:
        import native_firewall
        state, contract = load()
        native_firewall.installed(state, contract).dispatch('load')
        return
    if sys.argv[1] in ('condition', 'guard'):
        state, contract = load()
        guard(state, contract)
    else:
        raw = sys.stdin.buffer.read(65537)
        require(len(raw) <= 65536, 'native request exceeds its bound')
        import json
        if sys.argv[1:] == ['migration-export']:
            result=control(json_value(raw),private_export=True)
            require(isinstance(result,bytes) and len(result)<=4096,'invalid private original response')
            sys.stdout.buffer.write(result)
        else:
            print(json.dumps(control(json_value(raw), carried=sys.argv[1:] == ['play']), separators=(',', ':')))


if __name__ == '__main__':
    try: main()
    except Exception:
        print('Native runtime ownership or startup verification failed', file=sys.stderr)
        sys.exit(255 if sys.argv[1:] in (['condition'], ['gateway-condition'], ['proof-condition']) else 255 if len(sys.argv)==3 and sys.argv[1]=='migration-run-condition' else 1)

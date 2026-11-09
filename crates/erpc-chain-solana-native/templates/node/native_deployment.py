# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fence source-build continuations independently of the approved runtime."""
import fcntl
import hashlib
import os
import re
from native_files import atomic, json_value, read, require, root_directory, sync_file, sync_directory
from native_state import token
import native_accounts as accounts
import native_build_jobs as jobs
import native_helpers as helpers
import native_process as process
import native_publish as publication
import native_runtime_unit as units
import native_toolchain as toolchain
import native_custody as custody
import native_host as host
import native_tuning as tuning
import native_source_floor as source_floor
import native_migration_settings as migration_settings


def source(revision, network):
    directory = helpers.verify(revision)
    raw = read(directory / 'catalog.json', 65536)
    catalog = json_value(raw)
    require(network in ('mainnet', 'testnet'), 'invalid native build network')
    return raw, catalog, catalog['networks'][network]


def pending(state, contract, intent):
    operation = state.current(contract, token(intent))
    target = operation['target']
    require(set(target) == {'network', 'version', 'commit', 'catalog_sha256', 'helper_revision', 'mode', 'identity', 'build_intent'},
            'native deployment target fields differ')
    raw, catalog, profile = source(target['helper_revision'], contract['network'])
    expected = jobs.request(raw, contract['network'], intent)
    require(all(target[key] == expected[key] for key in ('network', 'version', 'commit', 'catalog_sha256')),
            'native deployment source differs from its authorized target')
    source_floor.check(state, contract, source_floor.from_profile(profile))
    units.arguments(contract, catalog, intent, target['mode'], target['identity'], migration_settings.load(state, contract))
    return operation, raw, catalog, profile


def authorize(state, contract, request):
    """The root caller owns the short operation lock; this never halts the runtime."""
    require(set(request) == {'action', 'contract', 'intent', 'mode', 'identity', 'operation'}
            and request['contract'] == contract and request['action'] == 'authorize-build',
            'invalid native deployment authorization')
    intent = token(request['intent']); state.owner(contract); state.recovery_clear(contract)
    require(request['operation'] in ('deploy', 'update', 'update-config'), 'unsupported native build operation')
    # Consensus admission belongs to the separate activation transition.
    require(request['mode'] in ('sync', 'rpc', 'validator'), 'unsupported native build role')
    accounts.verify(state, contract)
    revision = helpers.publish()
    raw, catalog, profile = source(revision, contract['network'])
    units.arguments(contract, catalog, intent, request['mode'], request['identity'], migration_settings.load(state, contract))
    previous = None
    if (state.directory / 'active.json').exists():
        previous = state.get('active.json')['receipt']
        _, _, old_profile = source(previous['helper_revision'], contract['network'])
        require(old_profile['genesis'] == profile['genesis'], 'native data cannot be moved to a different genesis')
        require(previous['mode'] == request['mode'] and previous['identity'] == request['identity'],
                'native update cannot replace the original runtime role or identity')
    if request['mode'] == 'validator':
        require(previous is not None and previous['mode'] == 'validator',
                'initial build cannot authorize validator activation')
        import native_activation
        # Preparation may precede explicit original-key restoration. Delivery
        # and startup still verify the recovered original material below.
        native_activation.approved(state, contract, previous['validator'], check_custody=False)
    desired = jobs.request(raw, contract['network'], intent)
    source_floor.check(state, contract, source_floor.from_profile(profile))
    target = {key: desired[key] for key in ('network', 'version', 'commit', 'catalog_sha256')}
    target.update(helper_revision=revision, mode=request['mode'], identity=request['identity'], build_intent=intent)
    reused = None
    if request['operation'] == 'update-config':
        require(previous is not None, 'configuration update requires an installed native runtime')
        reused = previous['build']
        target['build_intent'] = token(reused['request']['intent'])
        require(reused['request'] == jobs.request(raw, contract['network'], target['build_intent'])
                and reused['source'] == {key: profile[key] for key in ('commit', 'cargo_lock_sha256', 'rust')},
                'configuration update cannot change native source; use update')
        publication.verify(units.RELEASES / target['build_intent'], reused)
    if (state.directory / 'pending.json').exists():
        previous = state.get('pending.json')
        require(previous['intent'] == intent and previous['target'] == target and previous['action'] == request['operation'],
                'resolve the previous build before authorizing another request')
        # A stopped or superseded request cannot be revived by a late retry.
        state.current(contract, intent)
    else:
        state.authorize(contract, intent, target, request['operation'])
    if reused is not None:
        state.put('candidate-' + intent + '.json', reused)
    return {'intent': intent, 'target': target, 'runtime_changed': False}


def install_toolchain(state, contract, intent):
    """Uses its own public-cache lock, never the node-operation lock.

    Stop remains available during downloads. A cancelled download can finish
    populating the public cache but cannot authorize a build or runtime cutover.
    """
    _, _, _, profile = pending(state, contract, intent)
    root_directory(jobs.TOOLCHAINS, create=True)
    fd = os.open(jobs.TOOLCHAINS, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        pending(state, contract, intent)
        toolchain.install(profile, jobs.TOOLCHAINS)
        pending(state, contract, intent)
    finally:
        os.close(fd)
    return {'intent': intent, 'toolchain_ready': True, 'runtime_changed': False}


def step(state, contract, intent, phase):
    """Submit or inspect a bounded build phase under the caller's operation lock."""
    require(phase in ('prepare', 'fetch', 'compile', 'publish'), 'invalid native build phase')
    operation, _, _, _ = pending(state, contract, intent)
    require(operation['action'] in ('deploy', 'update'), 'configuration update reuses its verified build')
    plan = accounts.verify(state, contract)
    revision = operation['target']['helper_revision']
    authority = build_authority(contract, intent, revision, plan['builder'])
    authority_name = 'build-authority-' + token(intent) + '.json'
    if phase == 'prepare':
        if (state.directory / authority_name).exists():
            require(state.get(authority_name) == authority, 'native build ownership changed')
        else:
            state.put(authority_name, authority)
        sync_file(state.directory / authority_name); sync_directory(state.directory)
        jobs.create(state, contract, intent, revision)
        return {'intent': intent, 'phase': phase, 'state': 'prepared', 'runtime_changed': False}
    require(state.get(authority_name) == authority, 'native build phase lacks its original authority')
    if phase in ('fetch', 'compile'):
        completed_name = 'build-' + phase + '-completed-' + token(intent) + '.json'
        if (state.directory / completed_name).exists():
            require(state.get(completed_name) == authority, 'native completed build phase differs')
            sync_file(state.directory / completed_name); sync_directory(state.directory)
            return {'intent': intent, 'phase': phase, 'state': 'complete', 'runtime_changed': False}
        result = jobs.start(state, contract, intent, phase, revision,
                            lambda: process.assert_quiescent(plan['builder']['uid']))
        if result == 'complete': state.put(completed_name, authority)
        return {'intent': intent, 'phase': phase, 'state': result, 'runtime_changed': False}
    if (state.directory / ('candidate-' + token(intent) + '.json')).exists():
        candidate(state, contract, intent)
        return {'intent': intent, 'phase': 'publish', 'state': 'complete', 'runtime_changed': False}
    receipt = jobs.finish(state, contract, intent, revision)
    state.current(contract, intent)
    state.put('candidate-' + token(intent) + '.json', receipt)
    return {'intent': intent, 'phase': 'publish', 'state': 'complete', 'runtime_changed': False}


def candidate(state, contract, intent):
    operation, raw, _, profile = pending(state, contract, intent)
    receipt = state.get('candidate-' + token(intent) + '.json')
    build_intent = token(operation['target']['build_intent'])
    require(receipt['request'] == jobs.request(raw, contract['network'], build_intent)
            and receipt['source'] == {key: profile[key] for key in ('commit', 'cargo_lock_sha256', 'rust')},
            'native candidate belongs to another source or build request')
    publication.verify(units.RELEASES / build_intent, receipt)
    state.current(contract, intent)
    return operation, receipt


def build_authority(contract, intent, revision, builder):
    token(intent)
    require(re.fullmatch('[a-f0-9]{64}', revision) and type(builder['uid']) is int
            and type(builder['gid']) is int and 20000 <= builder['uid'] <= 60000
            and builder['uid'] == builder['gid'], 'invalid original build account')
    definitions = {}
    for phase in ('fetch', 'compile'):
        name, definition = jobs.unit(revision, intent, phase)
        definitions[name] = hashlib.sha256(definition.encode()).hexdigest()
    return {'contract': contract, 'intent': intent, 'helper_revision': revision,
            'builder': {key: builder[key] for key in ('uid', 'gid')}, 'units': definitions}


def cancel_builds(state, contract, run=None):
    """Retained numeric/unit authority remains usable when source/NSS checks fail."""
    if run is None:
        from native_runtime_control import systemctl
        run = systemctl
    state.owner(contract)
    original = state.get('accounts.json')
    require(set(original) in ({'contract', 'accounts'}, {'contract', 'accounts', 'opening_protocol'})
            and original['contract'] == contract
            and ('opening_protocol' not in original or type(original['opening_protocol']) is int and original['opening_protocol'] == 1),
            'native builder ownership differs')
    accounts.validate_plan(original['accounts'])
    builder = original['accounts']['builder']
    if not (state.directory / 'pending.json').exists():
        process.assert_quiescent(builder['uid'])
        return
    intent = token(state.get('pending.json')['intent'])
    names = [jobs.unit_name(intent, phase) for phase in ('fetch', 'compile')]
    path = state.directory / ('build-authority-' + intent + '.json')
    authority = state.get(path.name) if path.exists() else None
    if authority is not None:
        require(set(authority) == {'contract', 'intent', 'helper_revision', 'builder', 'units'}
                and authority['contract'] == contract and authority['intent'] == intent
                and authority['builder'] == {key: builder[key] for key in ('uid', 'gid')}
                and set(authority['units']) == set(names)
                and all(isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value)
                        for value in authority['units'].values()), 'retained build authority differs')
    root_directory(jobs.UNITS)
    failures = []
    for name in names:
        try:
            definition = jobs.UNITS / name
            overrides = jobs.UNITS / (name + '.d')
            if overrides.exists() or overrides.is_symlink():
                root_directory(overrides)
                require(not any(overrides.iterdir()), 'source-build service has unknown overrides')
            if definition.exists() or definition.is_symlink():
                require(authority is not None and hashlib.sha256(read(definition)).hexdigest() == authority['units'][name],
                        'source-build shutdown cannot adopt an unknown service')
                run(['daemon-reload'])
                run(['stop', name], timeout=180)
            else:
                require(run(['show', name, '--property=LoadState', '--value'], allowed=(0, 1)).strip() == 'not-found',
                        'source-build definition is absent while its unit remains loaded')
        except Exception:
            failures.append(name)
    try: process.assert_quiescent(builder['uid'])
    except Exception: failures.append('quiescence')
    require(not failures, 'one or more owned source-build jobs could not be stopped')


def recover_cutover(state, contract, intent, run=None):
    """Archive one explicitly selected interrupted cutover; never start or erase data.

    A later deployment receives a fresh intent. Ciphertext and build/runtime
    receipts remain intact, including original pending credential publication.
    """
    from native_runtime_control import shutdown_all, systemctl
    run = systemctl if run is None else run
    state.owner(contract); token(intent)
    name = 'cutover-recovery.json'
    previous = state.get(name) if (state.directory / name).exists() else None
    if previous is not None:
        require(previous.get('contract') == contract and previous.get('phase') in ('prepared', 'complete'),
                'cutover recovery authority differs')
        if previous['intent'] == intent and previous['phase'] == 'complete':
            for file in ('pending.json', 'cutover.json'):
                require(not (state.directory / file).exists() or state.get(file)['intent'] != intent,
                        'completed cutover recovery still has an old live operation')
            sync_file(state.directory / name); sync_directory(state.directory)
            return {'recovered': True, 'already_recovered': True, 'runtime_started': False, 'data_preserved': True}
        require(previous['phase'] == 'complete' or previous['intent'] == intent,
                'another cutover recovery must finish first')
    journal = previous if previous is not None and previous['phase'] == 'prepared' else None
    if journal is None:
        cutover = state.get('cutover.json'); operation = state.get('pending.json')
        require(cutover['intent'] == intent and operation['intent'] == intent
                and all(cutover[key] == operation[key] for key in ('halt', 'target')),
                'explicit recovery must identify the original incomplete cutover')
        imports = {}
        for role in ('sync', 'validator', 'rpc'):
            file = 'identity-import-' + role + '.json'
            if (state.directory / file).exists():
                value = state.get(file)
                require(value['contract'] == contract and value['intent'] == intent and value['role'] == role,
                        'incomplete identity import belongs to another operation')
                imports[file] = value
        journal = {'contract': contract, 'intent': intent, 'phase': 'prepared',
                   'cutover': cutover, 'pending': operation, 'imports': imports}
    require(set(journal) == {'contract', 'intent', 'phase', 'cutover', 'pending', 'imports'}
            and journal['intent'] == intent and journal['cutover']['intent'] == intent
            and journal['pending']['intent'] == intent, 'invalid original cutover recovery journal')
    for file, value in [('cutover.json', journal['cutover']), ('pending.json', journal['pending']), *journal['imports'].items()]:
        require(file in ('cutover.json', 'pending.json', 'identity-import-sync.json', 'identity-import-validator.json', 'identity-import-rpc.json'),
                'unknown cutover recovery entry')
        if (state.directory / file).exists():
            require(state.get(file) == value, 'a newer operation cannot be canceled by old cutover recovery')
    # Even a failed first persistence barrier attempts every owned shutdown.
    state.stop(contract, lambda: shutdown_all(state, contract, run), retired=state.halt()['retired'])
    state.put(name, journal); sync_file(state.directory / name); sync_directory(state.directory)
    archive = 'recovered-cutover-' + intent + '.json'
    if (state.directory / archive).exists(): require(state.get(archive) == journal, 'retained cutover recovery archive differs')
    else: state.put(archive, journal)
    sync_file(state.directory / archive); sync_directory(state.directory)
    # Only private operation metadata is retired. Original credential receipts
    # and every encrypted byte are retained. The next import must still prove
    # the same original key; it can finish an already receipted ciphertext.
    for file in journal['imports']: state.remove(file)
    state.remove('pending.json')
    state.remove('cutover.json')
    state.put(name, dict(journal, phase='complete'))
    sync_file(state.directory / name); sync_directory(state.directory)
    return {'recovered': True, 'already_recovered': False, 'runtime_started': False, 'data_preserved': True}


def abandon(state, contract, intent, run=None):
    """Explicitly cancel a build without changing the approved runtime generation."""
    state.owner(contract); token(intent)
    operation = state.get('pending.json')
    require(operation['intent'] == intent and not (state.directory / 'cutover.json').exists(),
            'build cancellation cannot discard a different or incomplete runtime cutover')
    try:
        state.put('intent-fence.json', {'intent': None, 'halt': state.halt()['generation']})
    except Exception:
        cancel_builds(state, contract, run)
        raise
    cancel_builds(state, contract, run)
    state.put('abandoned-build-' + intent + '.json', operation)
    state.remove('pending.json')
    return {'intent': intent, 'build_cancelled': True, 'runtime_changed': False, 'data_preserved': True}


def begin_runtime(state, contract, intent, run=None):
    """Only a verified completed candidate may fence and stop the old runtime."""
    from native_runtime_control import shutdown_all, systemctl
    run = systemctl if run is None else run
    operation, _ = candidate(state, contract, intent)
    accounts.verify(state, contract)
    host.capacity(state, contract)
    tuning.verify(state, contract)
    source_floor.initialize(state, contract)
    if operation['action'] == 'activate-validator':
        import native_activation
        native_activation.before_cutover(state, contract, intent, run)
    state.begin(contract, intent, lambda: shutdown_all(state, contract, run))
    return {'intent': intent, 'runtime_stopped': True, 'mode': operation['target']['mode'],
            'identity': operation['target']['identity'], 'credential_import_required': True}


def install_runtime(state, contract, intent, firewall, run=None):
    """Publish one unit while cutover prevents credential delivery or startup."""
    from native_runtime_control import firewall as confirmed, shutdown, systemctl
    run = systemctl if run is None else run
    operation, build = candidate(state, contract, intent)
    target = operation['target']; cutover = state.get('cutover.json')
    require(all(cutover[key] == operation[key] for key in ('intent', 'halt', 'target')),
            'native runtime installation requires its original fenced cutover')
    plan = accounts.verify(state, contract)
    node = {key: plan['node'][key] for key in ('uid', 'gid')}
    _, catalog, _ = source(target['helper_revision'], contract['network'])
    shutdown(state, contract, run)
    process.assert_quiescent(node['uid'])
    identity = custody.complete(state, contract, target['mode'])
    require(identity['public'] == target['identity'], 'native runtime identity differs from the authorized target')
    receipt = {'build': build, 'mode': target['mode'], 'identity': target['identity'],
               'helper_revision': target['helper_revision'], 'cipher_sha256': identity['cipher_sha256'],
               'account': node, 'firewall': firewall}
    if target['mode'] == 'validator':
        import native_activation
        receipt['validator'] = native_activation.finish(state, contract, intent, run)
    confirmed(receipt)
    if contract['profile'] == 'agave-native-rpc':
        import native_gateway
        receipt['gateway'] = native_gateway.install(state, contract, intent, target['helper_revision'], run, host.command)
    migration = migration_settings.load(state, contract)
    if migration is not None:
        migration_settings.publish(migration)
        receipt['migration'] = migration
    definition = units.render(contract, catalog, build['request']['intent'], target['helper_revision'],
                              target['mode'], target['identity'], node, migration)
    receipt['unit_sha256'] = hashlib.sha256(definition.encode()).hexdigest()
    # Authenticate and drain the previously owned unit before recording the new
    # digest: an unknown on-disk unit must not acquire ownership by coincidence.
    state.current(contract, intent)
    state.put('runtime-install.json', {'contract': contract, 'intent': intent, 'receipt': receipt})
    sync_file(state.directory / 'runtime-install.json'); sync_directory(state.directory)
    root_directory(units.UNITS)
    atomic(units.UNITS / units.UNIT, definition.encode(), 0o644)
    process.assert_quiescent(node['uid'])
    state.current(contract, intent)
    run(['daemon-reload'])
    return {'intent': intent, 'unit_installed': True, 'started': False}


def activate_runtime(state, contract, intent, run=None):
    """Consume deployment authority only after the exact service really starts."""
    from native_runtime_control import qualify, service, shutdown_all, status, systemctl
    run = systemctl if run is None else run
    operation, build = candidate(state, contract, intent)
    installed = state.get('runtime-install.json')
    require(set(installed) == {'contract', 'intent', 'receipt'} and installed['contract'] == contract
            and installed['intent'] == intent and installed['receipt']['build'] == build,
            'native runtime candidate differs from its installation receipt')
    receipt = installed['receipt']
    require(all(receipt[key] == operation['target'][key] for key in ('mode', 'identity', 'helper_revision')),
            'native runtime installation differs from the authorized role')
    # qualify accepts an explicit receipt; the cutover gate remains closed until
    # every source/custody/unit/mount/firewall check has passed.
    prospective = dict(operation, receipt=receipt)
    _, profile, _, _ = qualify(state, contract, prospective)
    try:
        source_floor.claim(state, contract, source_floor.from_profile(profile))
        if (state.directory / 'cutover.json').exists():
            process.assert_quiescent(receipt['account']['uid'])
            state.publish(contract, intent, receipt)
        else:
            require(state.guard(contract) == {key: prospective[key] for key in ('intent', 'halt', 'target', 'receipt')},
                    'completed runtime publication does not match this original pending operation')
        run(['daemon-reload'])
        service(receipt['account'], run)
        run(['enable', units.UNIT])
        run(['start', units.UNIT], timeout=210)
        observed = service(receipt['account'], run)
        require(observed['ActiveState'] == 'active' and observed['SubState'] == 'running'
                and observed['MainPID'] > 0, 'native runtime activation did not start its service')
        if contract['profile'] == 'agave-native-rpc':
            import native_gateway
            native_gateway.start(state, contract, receipt['gateway'], run)
        state.consume(contract, intent)
    except Exception:
        state.stop(contract, lambda: shutdown_all(state, contract, run))
        raise
    return {'intent': intent, 'runtime_started': True, 'observation': status(state, contract, run)}

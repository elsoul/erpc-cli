# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Conservative original-data opening authority, independent of candidate builds."""
import re
import stat
import hashlib
import fcntl
import functools
import os
from native_files import json_value, require, sync_file, sync_directory
import native_accounts as accounts
import native_runtime_unit as units

COMPLETE = 'opening-floor.json'
PENDING = 'opening-floor-pending.json'
FULL = {'version', 'commit', 'cargo_lock_sha256', 'rust', 'rust_manifest_sha256'}
MINIMUM = {'version', 'commit'}


def serialized(operation):
    """Boot guards and the controller share one original-directory lock.

    The boot guard cannot take the controller lock while systemctl start waits
    for it. A separate nonblocking directory lock serializes only floor writes.
    """
    @functools.wraps(operation)
    def locked(state, *args, **kwargs):
        fd = os.open(state.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                    and not info.st_mode & 0o022, 'unsafe original opening authority directory')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return operation(state, *args, **kwargs)
        finally:
            os.close(fd)
    return locked


def version(value):
    require(isinstance(value, str) and len(value) <= 128, 'invalid native source version')
    match = re.fullmatch(r'v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?', value)
    require(match is not None, 'native source version is not canonical SemVer')
    core = tuple(map(int, match.groups()[:3])); pre = match[4]
    if pre is None: return (*core, 1, ())
    labels = []
    for label in pre.split('.'):
        require(not (label.isdecimal() and len(label) > 1 and label.startswith('0')), 'numeric prerelease has leading zeroes')
        labels.append((0, int(label)) if label.isdecimal() else (1, label))
    return (*core, 0, tuple(labels))


def source(value):
    require(isinstance(value, dict) and set(value) in (MINIMUM, FULL), 'native opening source fields differ')
    version(value['version'])
    result = dict(value, version=value['version'].removeprefix('v'))
    require(isinstance(value['commit'], str) and re.fullmatch('[a-f0-9]{40}', value['commit']), 'invalid native source commit')
    if set(value) == FULL:
        version(value['rust'])
        for name in ('cargo_lock_sha256', 'rust_manifest_sha256'):
            require(isinstance(value[name], str) and re.fullmatch('[a-f0-9]{64}', value[name]), 'invalid native compiler/source binding')
    return result


def from_profile(profile):
    return source({name: profile[name] for name in FULL})


def compatible(target, original):
    target, original = source(target), source(original)
    order, previous = version(target['version']), version(original['version'])
    require(order >= previous, 'native target is below the original data-opening version')
    if order == previous:
        require(all(target.get(name) == value for name, value in original.items()),
                'same-version native source or compiler binding changed')
    return order


def upgrade_record(state, contract):
    path = state.directory / 'opening-upgrade.json'
    require(not path.is_symlink(), 'native opening upgrade has an indirect record')
    if not path.exists(): return None
    value = state.get(path.name)
    require(isinstance(value, dict) and set(value) == {'schema', 'contract', 'history', 'accounts', 'account_intent', 'data', 'active', 'phase'}
            and type(value['schema']) is int and value['schema'] == 1 and value['contract'] == contract
            and type(value['account_intent']) is bool and value['phase'] in ('prepared', 'complete')
            and isinstance(value['accounts'], dict) and set(value['accounts']) == {'contract', 'accounts'}
            and value['accounts']['contract'] == contract, 'original source-history upgrade record differs')
    history = value['history']
    require(isinstance(history, dict) and set(history) == {'document_sha256', 'highest'}
            and isinstance(history['document_sha256'], str) and re.fullmatch('[a-f0-9]{64}', history['document_sha256'])
            and isinstance(history['highest'], dict) and set(history['highest']) == MINIMUM
            and source(history['highest']) == history['highest'], 'original source-history evidence is invalid')
    accounts.validate_plan(value['accounts']['accounts'])
    return value


def protocol(state, contract, upgrading=False):
    state.owner(contract)
    if state.migration is None and state.get('owner.json').get('migration') is not None:
        import native_migration_cutover
        native_migration_cutover.committed(state,contract)
    for name in (COMPLETE, PENDING, 'active.json', 'opening-upgrade.json', 'accounts-intent.json'):
        require(not (state.directory / name).is_symlink(), 'native opening authority contains an indirect record')
    receipt = state.get('accounts.json')
    require(set(receipt) == {'contract', 'accounts', 'opening_protocol'} and receipt['contract'] == contract
            and type(receipt['opening_protocol']) is int and receipt['opening_protocol'] == 1,
            'native host requires explicit original source-history upgrade')
    journal = upgrade_record(state, contract)
    if journal is not None:
        require(upgrading or journal['phase'] == 'complete', 'original source-history upgrade is incomplete')
        require(receipt['accounts'] == journal['accounts']['accounts'], 'upgraded original account reservation changed')
    return receipt['accounts']['node']


def binding(state, contract, upgrading=False):
    node = protocol(state, contract, upgrading)
    return data_binding(state, contract, node)


def data_binding(state, contract, node):
    state.owner(contract)
    require(state.get('data.json') == {'contract': contract, 'uid': node['uid'], 'gid': node['gid']},
            'native opening authority belongs to another data owner')
    paths = {}
    for kind, mount in units.MOUNTS.items():
        info = (mount / 'data').lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == node['uid'] and info.st_gid == node['gid']
                and info.st_mode & 0o7777 == 0o700, 'native opening data directory authority differs')
        # Kernel device numbers can change on reboot. Startup separately verifies
        # the currently mounted device against this original UUID; only the
        # directory inode inside that filesystem is persistent authority here.
        paths[kind] = {'uuid': contract['volumes'][kind], 'inode': info.st_ino}
    return {'contract': contract, 'account': {key: node[key] for key in ('uid', 'gid')}, 'data': paths}


def records(state, contract, upgrading=False):
    protocol(state, contract, upgrading)
    found = {}
    for name in (COMPLETE, PENDING):
        path = state.directory / name
        if path.exists() or path.is_symlink():
            value = state.get(name)
            require(isinstance(value, dict) and set(value) == {'schema', 'binding', 'highest'}
                    and type(value['schema']) is int and value['schema'] == 1
                    and value['binding'] == binding(state, contract, upgrading), 'native opening record ownership changed')
            if value['highest'] is not None:
                require(source(value['highest']) == value['highest'], 'native opening record source is not canonical')
                require(name != PENDING or set(value['highest']) == FULL, 'pending opening lacks qualified source/compiler identity')
            else:
                require(name == COMPLETE, 'pending native opening lacks its source')
            found[name] = value
    journal = upgrade_record(state, contract)
    if journal is not None:
        require(found or upgrading and journal['phase'] == 'prepared', 'original source-history opening records are missing')
        if found:
            previous = highest(found)
            require(previous is not None, 'original historical source floor is missing')
            compatible(previous, journal['history']['highest'])
    return found


def highest(found):
    result = None
    for record in found.values():
        candidate = record['highest']
        if candidate is None: continue
        if result is None: result = candidate; continue
        if version(candidate['version']) > version(result['version']):
            result = candidate
        elif version(candidate['version']) == version(result['version']):
            # A historical minimum may lack compiler qualification; once known,
            # retain the stronger complete source, never erase it on recovery.
            detailed, minimal = (candidate, result) if len(candidate) >= len(result) else (result, candidate)
            compatible(detailed, minimal); result = detailed
    return result


def sync(state, found):
    for name, value in found.items():
        require(state.get(name) == value, 'native opening record changed before durability check')
        sync_file(state.directory / name)
    sync_directory(state.directory)
    for name, value in found.items():
        require(state.get(name) == value, 'native opening record changed during durability check')


def existing_runtime(state):
    return any((state.directory / name).exists() or (state.directory / name).is_symlink()
               for name in ('active.json', 'runtime-install.json', 'cutover.json'))


def check(state, contract, target):
    """Admission/status check only: does not raise a floor or claim durability."""
    target = source(target)
    found = records(state, contract)
    require(found or not existing_runtime(state), 'native opening history is missing; do not reconstruct it from the current pin')
    previous = highest(found)
    require(previous is not None or not (state.directory / 'active.json').exists(),
            'native opened runtime lacks its original source history')
    if previous is not None: compatible(target, previous)
    return previous


@serialized
def initialize(state, contract, historical=None):
    """Bind fresh empty data, or an explicitly verified historical upgrade."""
    owner = binding(state, contract, upgrading=historical is not None)
    found = records(state, contract, upgrading=historical is not None)
    if found:
        require(highest(found) is not None or not (state.directory / 'active.json').exists(),
                'native opened runtime lacks its original source history')
        if historical is not None:
            previous = highest(found)
            require(previous is not None, 'historical upgrade cannot replace a fresh opening baseline')
            compatible(previous, source(historical))
        sync(state, found)
        if COMPLETE not in found:
            retained = found[PENDING]
            state.put(COMPLETE, retained)
            sync(state, {**found, COMPLETE: retained})
        return
    if historical is None:
        require(not existing_runtime(state) and not any(any((mount / 'data').iterdir()) for mount in units.MOUNTS.values()),
                'native opening baseline cannot adopt used or unrecorded data')
    else:
        historical = source(historical)
    record = {'schema': 1, 'binding': owner, 'highest': historical}
    state.put(COMPLETE, record)
    sync(state, {COMPLETE: record})


@serialized
def claim(state, contract, target):
    """Persist before native DB opening; a visible pending upgrade never lowers."""
    target = source(target)
    require(set(target) == FULL, 'DB opening requires fully qualified native source and compiler')
    previous = check(state, contract, target)
    found = records(state, contract)
    require(found, 'native opening baseline is not prepared')
    sync(state, found)
    desired = {'schema': 1, 'binding': binding(state, contract), 'highest': target}
    if previous != target:
        state.put(PENDING, desired)
        sync(state, {PENDING: desired})
    if found.get(COMPLETE) != desired:
        state.put(COMPLETE, desired)
    # Keep the last pending intent as another restrictive receipt. Recovery and
    # retirement never remove either original data-opening record.
    current = records(state, contract)
    require(highest(current) == target and current[COMPLETE] == desired, 'native opening commitment differs')
    sync(state, current)
    return target


def historical_document(raw, network):
    require(isinstance(raw, str) and 0 < len(raw.encode()) <= 16384, 'original client history exceeds its bound')
    value = json_value(raw.encode())
    require(isinstance(value, dict) and set(value) == {'schema', 'client', 'network', 'version', 'commit'}
            and type(value['schema']) is int and value['schema'] == 1 and value['client'] == 'agave'
            and value['network'] == network, 'original client history has another schema, client or network')
    return {'document_sha256': hashlib.sha256(raw.encode()).hexdigest(),
            'highest': source({key: value[key] for key in ('version', 'commit')})}


def observation(state, contract):
    found = records(state, contract)
    original = highest(found)
    require(original is not None or not (state.directory / 'active.json').exists(),
            'native opened runtime lacks its original source history')
    phase = None
    if (state.directory / 'opening-upgrade.json').exists():
        upgrade = state.get('opening-upgrade.json')
        require(upgrade['contract'] == contract and upgrade['phase'] in ('prepared', 'complete'),
                'source-history upgrade owner differs')
        phase = upgrade['phase']
    return {'opening_protocol': 1, 'prepared': COMPLETE in found, 'highest': original, 'upgrade_phase': phase}


def upgrade(state, contract, document, current_profile, run):
    """Explicit stopped upgrade of a previously managed native host, not Solv adoption."""
    from native_runtime_control import selected, unit_definition, shutdown_all
    import native_mounts
    historical = historical_document(document, contract['network'])
    compatible(from_profile(current_profile), historical['highest'])
    state.owner(contract)
    name = 'opening-upgrade.json'
    for entry in (name, 'active.json', 'accounts-intent.json', COMPLETE, PENDING):
        require(not (state.directory / entry).is_symlink(), 'source-history upgrade cannot replace an indirect original record')
    previous = upgrade_record(state, contract)
    if previous is not None:
        require(set(previous) == {'schema', 'contract', 'history', 'accounts', 'account_intent', 'data', 'active', 'phase'}
                and type(previous['schema']) is int and previous['schema'] == 1
                and previous['contract'] == contract and previous['history'] == historical
                and isinstance(previous['accounts'], dict) and set(previous['accounts']) == {'contract', 'accounts'}
                and previous['accounts']['contract'] == contract
                and type(previous['account_intent']) is bool and previous['phase'] in ('prepared', 'complete'),
                'resume the original source-history upgrade without replacing its evidence')
        if previous['phase'] == 'complete':
            accounts.verify(state, contract)
            initialize(state, contract, historical['highest'])
            sync_file(state.directory / name); sync_directory(state.directory)
            return {'source_authority_upgraded': True, 'already_upgraded': True, 'runtime_started': False}
    require(not any((state.directory / entry).exists() or (state.directory / entry).is_symlink()
                    for entry in ('pending.json', 'cutover.json')),
            'finish or explicitly recover the original deployment before its source-history upgrade')
    state.recovery_clear(contract)
    plan = accounts.verify(state, contract, legacy=True)
    native_mounts.inspect(contract)
    original = state.get('accounts.json')
    observed_data = data_binding(state, contract, plan['node'])
    active = state.get('active.json') if (state.directory / 'active.json').exists() else None
    if active is not None:
        _, profile, _, definition = selected(contract, active)
        unit_definition(definition)
        compatible(historical['highest'], {key: profile[key] for key in MINIMUM})
    account_intent = (state.directory / 'accounts-intent.json').exists()
    if previous is None:
        require(set(original) == {'contract', 'accounts'}, 'host already has protected opening authority; use normal init')
        require(not any((state.directory / entry).exists() or (state.directory / entry).is_symlink()
                        for entry in (COMPLETE, PENDING)), 'unbound original opening records cannot be adopted')
        previous = {'schema': 1, 'contract': contract, 'history': historical, 'accounts': original,
                    'account_intent': account_intent, 'data': observed_data, 'active': active, 'phase': 'prepared'}
        state.put(name, previous)
    protected = dict(previous['accounts'], opening_protocol=1)
    require(original in (previous['accounts'], protected) and account_intent == previous['account_intent']
            and observed_data == previous['data'] and active == previous['active'],
            'original accounts, data or approved runtime changed during source-history upgrade')
    if account_intent:
        require(state.get('accounts-intent.json') in (previous['accounts'], protected),
                'original account creation reservation changed')
    sync_file(state.directory / name); sync_directory(state.directory)
    state.stop(contract, lambda: shutdown_all(state, contract, run), retired=state.halt()['retired'])
    # The old closed decoder rejects this extra field before any native launch.
    # Stop/recovery in the new controller explicitly retain both known schemas.
    for entry in (['accounts.json', 'accounts-intent.json'] if account_intent else ['accounts.json']):
        if state.get(entry) != protected: state.put(entry, protected)
        sync_file(state.directory / entry); sync_directory(state.directory)
    accounts.verify(state, contract)
    initialize(state, contract, historical['highest'])
    state.put(name, dict(previous, phase='complete'))
    sync_file(state.directory / name); sync_directory(state.directory)
    return {'source_authority_upgraded': True, 'already_upgraded': False,
            'runtime_started': False, 'next_operation': 'deploy'}

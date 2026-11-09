# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Reserve exact isolated service identities before creating any account.

The root controller holds its operation lock for this short transaction. Unknown
existing accounts are not adopted, and every later launch rechecks NSS membership.
"""
import grp
import os
from pathlib import Path
import pwd
import re
import subprocess
from native_files import read, require, root_directory, sync_file, sync_directory

SPECS = {
    'node': ('erpc-solana', '/var/lib/erpc-solana'),
    'builder': ('erpc-solana-build', '/var/lib/erpc-solana-build'),
    'proof': ('erpc-solana-proof', '/var/lib/erpc-solana-proof'),
}
SHELL = '/usr/sbin/nologin'
TRUST_ANCHOR = Path('/')


def lookup(method, value):
    try:
        return method(value)
    except KeyError:
        return None


def execute(args):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30, check=False, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(result.returncode == 0, 'isolated service account creation failed; retry the original reservation')


def validate_plan(plan, specs=None):
    specs = SPECS if specs is None else specs
    require(isinstance(plan, dict) and set(plan) == set(specs), 'invalid service identity reservation')
    ids = set()
    for role, record in plan.items():
        name, home = specs[role]
        require(set(record) == {'name', 'home', 'shell', 'uid', 'gid'}
                and record['name'] == name and record['home'] == home and record['shell'] == SHELL
                and type(record['uid']) is int and type(record['gid']) is int
                and 20000 <= record['uid'] <= 60000 and record['uid'] == record['gid']
                and record['uid'] not in ids, 'service identity reservation differs from its fixed role')
        ids.add(record['uid'])


def verify_slot(record, missing=False):
    name, uid, gid = record['name'], record['uid'], record['gid']
    user, group = lookup(pwd.getpwnam, name), lookup(grp.getgrnam, name)
    by_uid, by_gid = lookup(pwd.getpwuid, uid), lookup(grp.getgrgid, gid)
    require((by_uid is None or by_uid.pw_name == name) and (by_gid is None or by_gid.gr_name == name),
            'reserved service UID or GID belongs to another account')
    def user_fields(value):
        return None if value is None else (value.pw_name, value.pw_uid, value.pw_gid, value.pw_dir, value.pw_shell)
    def group_fields(value):
        return None if value is None else (value.gr_name, value.gr_gid, frozenset(value.gr_mem))
    require(user_fields(user) == user_fields(by_uid) and group_fields(group) == group_fields(by_gid),
            'service name and numeric NSS resolution disagree')
    users, groups = pwd.getpwall(), grp.getgrall()
    require(len(users) <= 100000 and len(groups) <= 100000
            and not any((item.pw_uid == uid or item.pw_gid == gid) and item.pw_name != name for item in users)
            and not any(item.gr_gid == gid and item.gr_name != name for item in groups),
            'another account or group shares the reserved service identity')
    if group is not None:
        require(group.gr_gid == gid and set(group.gr_mem) <= {name}, 'service group is changed or shared')
    if user is not None:
        require(group is not None and user.pw_uid == uid and user.pw_gid == gid
                and user.pw_dir == record['home'] and user.pw_shell == record['shell'],
                'service UID, GID, home or shell differs from its original reservation')
        require(set(os.getgrouplist(name, gid)) == {gid}, 'service account inherited unapproved supplementary groups')
    if not missing:
        require(user is not None and group is not None, 'original service account is missing')
    return user, group


def plan_new(state, contract, specs=None):
    specs = SPECS if specs is None else specs
    state.owner(contract)
    users, groups = pwd.getpwall(), grp.getgrall()
    require(len(users) <= 100000 and len(groups) <= 100000, 'account namespace exceeds its bound')
    used = {user.pw_uid for user in users} | {user.pw_gid for user in users} | {group.gr_gid for group in groups}
    names = {spec[0] for spec in specs.values()}
    require(not any(user.pw_name in names for user in users) and not any(group.gr_name in names for group in groups),
            'unknown existing service account or group cannot be adopted')
    for name, home in specs.values():
        require(lookup(pwd.getpwnam, name) is None and lookup(grp.getgrnam, name) is None,
                'service account appeared during reservation')
        path = Path(home)
        root_directory(path.parent)
        if path.exists() or path.is_symlink():
            root_directory(path)
            entries = list(path.iterdir())
            if name == SPECS['node'][0] and state.directory == path / 'state' and entries == [state.directory]:
                root_directory(state.directory)
                expected={'owner.json','halt.json','intent-fence.json'}|({'migration.json'} if state.migration is not None else set())
                entries=list(state.directory.iterdir())
                require(len(entries)<=256 and expected<={item.name for item in entries},'new service home lacks initial ownership state')
                for item in entries:
                    if item.name in expected:continue
                    require(state.migration is not None and re.fullmatch(r'\.erpc-[a-f0-9]{32}',item.name),
                            'new service home contains unexpected lifecycle state')
                    read(item,1048576)
                state.owner(contract); state.halt()
                require(state.get('intent-fence.json') == {'intent': None, 'halt': state.halt()['generation']},
                        'new account reservation has unexpected deployment authority')
            else:
                require(not entries, 'unowned service home is not empty')
    available = (value for value in range(20000, 60001) if value not in used
                 and lookup(pwd.getpwuid, value) is None and lookup(grp.getgrgid, value) is None)
    result = {}
    for role, (name, home) in specs.items():
        selected = next(available, None)
        require(selected is not None, 'no unused dedicated service identity is available')
        result[role] = {'name': name, 'home': home, 'shell': SHELL, 'uid': selected, 'gid': selected}
    return result


def verify(state, contract, legacy=False):
    state.owner(contract)
    receipt = state.get('accounts.json')
    require(set(receipt) in ({'contract', 'accounts'}, {'contract', 'accounts', 'opening_protocol'}) and receipt['contract'] == contract,
            'service identity receipt belongs to another owner')
    require((legacy and 'opening_protocol' not in receipt)
            or type(receipt.get('opening_protocol')) is int and receipt['opening_protocol'] == 1,
            'native host requires explicit original source-history upgrade')
    plan = receipt['accounts']
    validate_plan(plan)
    for record in plan.values():
        verify_slot(record)
        root_directory(Path(record['home']))
    return plan


def synchronize(state, contract, records):
    """A visible rename is not evidence that its directory entry is durable."""
    state.owner(contract)
    root_directory(state.directory)
    state.directory.relative_to(TRUST_ANCHOR)
    for name, expected in records.items():
        require(state.get(name) == expected, 'original account reservation changed')
        sync_file(state.directory / name)
    directory = state.directory
    while True:
        sync_directory(directory)
        if directory == TRUST_ANCHOR: break
        directory = directory.parent
    state.owner(contract)
    for name, expected in records.items():
        require(state.get(name) == expected, 'account reservation changed during synchronization')


def ensure(state, contract, run=execute):
    state.owner(contract)
    if (state.directory / 'accounts.json').exists():
        plan = verify(state, contract)
        records = {'accounts.json': {'contract': contract, 'accounts': plan, 'opening_protocol': 1}}
        if (state.directory / 'accounts-intent.json').exists():
            records['accounts-intent.json'] = records['accounts.json']
        synchronize(state, contract, records)
        return plan
    intent_path = state.directory / 'accounts-intent.json'
    if intent_path.exists():
        intent = state.get('accounts-intent.json')
        require(set(intent) == {'contract', 'accounts', 'opening_protocol'} and intent['contract'] == contract
                and type(intent['opening_protocol']) is int and intent['opening_protocol'] == 1,
                'service account reservation belongs to another owner')
    else:
        intent = {'contract': contract, 'accounts': plan_new(state, contract), 'opening_protocol': 1}
        # No group/user command is allowed before this durable record exists.
        state.put('accounts-intent.json', intent)
    plan = intent['accounts']
    validate_plan(plan)
    # Check every reserved slot before changing the first one.
    for record in plan.values():
        verify_slot(record, missing=True)
    synchronize(state, contract, {'accounts-intent.json': intent})
    for record in plan.values():
        user, group = verify_slot(record, missing=True)
        if group is None:
            run(['/usr/sbin/groupadd', '--system', '--gid', str(record['gid']), record['name']])
        if user is None:
            run(['/usr/sbin/useradd', '--system', '--no-create-home', '--no-user-group', '--no-log-init',
                 '--uid', str(record['uid']), '--gid', str(record['gid']), '--home-dir', record['home'],
                 '--shell', record['shell'], record['name']])
        verify_slot(record)
        # Root-owned homes prevent ambient configuration injection. Per-job build
        # workspaces and native data are allocated separately to the exact UID.
        root_directory(Path(record['home']), create=True)
    state.put('accounts.json', intent)
    return verify(state, contract)

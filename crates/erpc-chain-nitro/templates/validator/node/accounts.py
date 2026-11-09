# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original numeric Nitro validator identities; never adopt an existing account."""
import scope
import grp
import os
from pathlib import Path
import pwd
import subprocess
from storage import directory, require, synchronize

SPECS = scope.ACCOUNTS
SHELL = '/usr/sbin/nologin'


def lookup(function, value):
    try: return function(value)
    except KeyError: return None


def user_fields(value):
    return None if value is None else (value.pw_name, value.pw_uid, value.pw_gid, value.pw_dir, value.pw_shell)


def group_fields(value):
    return None if value is None else (value.gr_name, value.gr_gid, tuple(sorted(value.gr_mem)))


def namespace():
    users, groups = pwd.getpwall(), grp.getgrall()
    require(len(users) <= 100000 and len(groups) <= 100000, 'NSS namespace exceeds its observation bound')
    return users, groups


def validate(records):
    require(isinstance(records, dict) and set(records) == set(SPECS), 'invalid original validator account roles')
    ids = set()
    for role, value in records.items():
        require(isinstance(value, dict) and set(value) == {'name', 'home', 'shell', 'uid', 'gid'}
                and (value['name'], value['home']) == SPECS[role] and value['shell'] == SHELL
                and type(value['uid']) is int and type(value['gid']) is int
                and 20000 <= value['uid'] <= 60000 and value['uid'] == value['gid']
                and value['uid'] not in ids, 'original validator account reservation changed')
        ids.add(value['uid'])
    return records


def slot(record, missing=False):
    name, uid, gid = record['name'], record['uid'], record['gid']
    user, by_uid = lookup(pwd.getpwnam, name), lookup(pwd.getpwuid, uid)
    group, by_gid = lookup(grp.getgrnam, name), lookup(grp.getgrgid, gid)
    require(user_fields(user) == user_fields(by_uid) and group_fields(group) == group_fields(by_gid),
            'direct NSS name and numeric observations disagree')
    users, groups = namespace()
    for observed in users:
        if observed.pw_name == name or observed.pw_uid == uid:
            require(user_fields(observed) == user_fields(user), 'enumerated service identity disagrees with direct NSS')
        require(observed.pw_name == name or observed.pw_gid != gid, 'original service primary group is shared')
    for observed in groups:
        if observed.gr_name == name or observed.gr_gid == gid:
            require(group_fields(observed) == group_fields(group), 'enumerated service group disagrees with direct NSS')
    if group is not None:
        require(group.gr_name == name and group.gr_gid == gid and set(group.gr_mem) <= {name},
                'original validator group has drifted or is shared')
    if user is not None:
        require(group is not None and user_fields(user) == (name, uid, gid, record['home'], record['shell']),
                'original validator UID, GID, home or shell has drifted')
        require(set(os.getgrouplist(name, gid)) == {gid}, 'validator account has supplementary authority')
    require(missing or user is not None and group is not None, 'original validator account is missing')
    return user, group


def plan():
    users, groups = namespace()
    names = {spec[0] for spec in SPECS.values()}
    require(not any(value.pw_name in names for value in users)
            and not any(value.gr_name in names for value in groups), 'unknown validator account cannot be adopted')
    for name, home in SPECS.values():
        require(lookup(pwd.getpwnam, name) is None and lookup(grp.getgrnam, name) is None,
                'unknown direct NSS validator account cannot be adopted')
        path = Path(home); directory(path.parent)
        if path.exists() or path.is_symlink():
            directory(path)
            require(not any(path.iterdir()) and path.lstat().st_mode & 0o005 == 0o005,
                    'unowned validator home is not empty or traversable')
    occupied = {v.pw_uid for v in users} | {v.pw_gid for v in users} | {v.gr_gid for v in groups}
    candidates = (uid for uid in range(20000, 60001) if uid not in occupied
                  and lookup(pwd.getpwuid, uid) is None and lookup(grp.getgrgid, uid) is None)
    records = {}
    for role, (name, home) in SPECS.items():
        uid = next(candidates, None)
        require(uid is not None, 'no isolated service UID/GID remains')
        records[role] = {'name': name, 'home': home, 'shell': SHELL, 'uid': uid, 'gid': uid}
    return validate(records)


def retained(state, expected):
    """Original numeric IDs for shutdown proof even when current NSS has drifted."""
    state.owner(expected)
    name = 'accounts.json' if (state.root / 'accounts.json').exists() else 'accounts-intent.json'
    value = state.get(name)
    require(set(value) == {'contract', 'accounts'} and value['contract'] == expected,
            'original validator account receipt belongs to another owner')
    return validate(value['accounts'])


def verify(state, expected):
    require((state.root / 'accounts.json').exists(), 'validator accounts are not durably established')
    records = retained(state, expected)
    for value in records.values():
        slot(value); home = Path(value['home']); directory(home)
        require(home.lstat().st_mode & 0o005 == 0o005, 'original validator home is not traversable')
    return records


def command(argv):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=30, check=False,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    require(result.returncode == 0, 'original validator account creation failed; resume the reserved IDs')


def ensure(state, expected, run=command):
    state.owner(expected)
    if (state.root / 'accounts.json').exists():
        records = verify(state, expected)
        synchronize(state.root / 'accounts.json')
        return records
    intent = state.root / 'accounts-intent.json'
    if not intent.exists():
        state.put('accounts-intent.json', {'contract': expected, 'accounts': plan()})
    records = retained(state, expected)
    for value in records.values(): slot(value, missing=True)
    # Re-establish a visible rename's durability BEFORE the first NSS mutation.
    synchronize(intent)
    for value in records.values():
        user, group = slot(value, missing=True)
        if group is None: run(['/usr/sbin/groupadd', '--system', '--gid', str(value['gid']), value['name']])
        if user is None:
            run(['/usr/sbin/useradd', '--system', '--no-create-home', '--no-user-group', '--no-log-init',
                 '--uid', str(value['uid']), '--gid', str(value['gid']), '--home-dir', value['home'],
                 '--shell', value['shell'], value['name']])
        slot(value)
        directory(Path(value['home']), create=True, mode=0o755)
    state.put('accounts.json', {'contract': expected, 'accounts': records})
    return verify(state, expected)

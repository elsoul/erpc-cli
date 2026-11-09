#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original EL/CL numeric identities; only Engine IPC shares a dedicated group."""
import grp
import os
import pwd

from arc_files import require
from av_files import HOME

SLOTS = {'execution': 'erpc-arc-el', 'consensus': 'erpc-arc-cl'}
ENGINE = 'erpc-arc-engine'


def lookup(function, key):
    try:
        return function(key)
    except KeyError:
        return None


def inventory():
    users, groups = pwd.getpwall(), grp.getgrall()
    require(len(users) <= 100000 and len(groups) <= 100000, 'NSS inventory exceeds its bound')
    return users, groups


def user_fields(value):
    return None if value is None else (value.pw_name, value.pw_uid, value.pw_gid,
                                      value.pw_dir, value.pw_shell)


def group_fields(value):
    return None if value is None else (value.gr_name, value.gr_gid, frozenset(value.gr_mem))


def reserve():
    users, groups = inventory()
    names = set(SLOTS.values()) | {ENGINE}
    require(not any(row.pw_name in names for row in users) and
            not any(row.gr_name in names for row in groups) and
            all(lookup(pwd.getpwnam, name) is None and lookup(grp.getgrnam, name) is None
                for name in names), 'unowned Arc validator NSS identity cannot be adopted')
    used = {row.pw_uid for row in users} | {row.pw_gid for row in users} | {row.gr_gid for row in groups}
    selected = []
    for number in range(999, 99, -1):
        if number not in used and lookup(pwd.getpwuid, number) is None and lookup(grp.getgrgid, number) is None:
            selected.append(number)
            if len(selected) == 3:
                break
    require(len(selected) == 3, 'three unused Arc validator system identities are required')
    return {'execution': selected[0], 'consensus': selected[1], 'engine': selected[2],
            'established': False}


def verify(record, missing=False):
    require(isinstance(record, dict) and set(record) == {'execution', 'consensus', 'engine', 'established'} and
            type(record['established']) is bool, 'original Arc validator accounts receipt is missing')
    numbers = [record[name] for name in ('execution', 'consensus', 'engine')]
    require(all(type(number) is int and 100 <= number <= 2147483647 and number != 65534
                for number in numbers) and len(set(numbers)) == 3,
            'original Arc validator numeric identities are invalid')
    users, groups = inventory()
    observed_users, observed_groups = {}, {}
    for role, name in SLOTS.items():
        number = record[role]
        named_users = [row for row in users if row.pw_name == name]
        named_groups = [row for row in groups if row.gr_name == name]
        by_name, by_id = lookup(pwd.getpwnam, name), lookup(pwd.getpwuid, number)
        group_name, group_id = lookup(grp.getgrnam, name), lookup(grp.getgrgid, number)
        require(len(named_users) <= 1 and len(named_groups) <= 1 and
                user_fields(by_name) == user_fields(by_id) == user_fields(named_users[0] if named_users else None) and
                group_fields(group_name) == group_fields(group_id) == group_fields(named_groups[0] if named_groups else None),
                'original Arc validator NSS lookup disagrees')
        require(not any((row.pw_uid == number or row.pw_gid == number) and row.pw_name != name for row in users) and
                not any(row.gr_gid == number and row.gr_name != name for row in groups),
                'original Arc validator numeric identity is shared')
        if group_name is not None:
            require(group_name.gr_gid == number and not group_name.gr_mem,
                    'original Arc validator private group changed')
        if by_name is not None:
            require(group_name is not None and by_name.pw_uid == number and by_name.pw_gid == number and
                    by_name.pw_dir == HOME + '/' + role and by_name.pw_shell == '/usr/sbin/nologin' and
                    set(os.getgrouplist(name, number)) == {number, record['engine']},
                    'original Arc validator account or supplementary groups changed')
        require(missing or (by_name is not None and group_name is not None),
                'established Arc validator account is absent')
        observed_users[role], observed_groups[role] = by_name, group_name
    engine = lookup(grp.getgrnam, ENGINE)
    rows = [row for row in groups if row.gr_name == ENGINE]
    require(len(rows) <= 1 and group_fields(engine) == group_fields(lookup(grp.getgrgid, record['engine'])) ==
            group_fields(rows[0] if rows else None), 'original Engine IPC group lookup disagrees')
    require(not any(row.pw_uid == record['engine'] or row.pw_gid == record['engine'] or row.pw_name == ENGINE
                    for row in users) and lookup(pwd.getpwnam, ENGINE) is None and
            lookup(pwd.getpwuid, record['engine']) is None and
            not any(row.gr_gid == record['engine'] and row.gr_name != ENGINE for row in groups),
            'Engine IPC group is shared with an unowned identity')
    if engine is not None:
        require(engine.gr_gid == record['engine'] and set(engine.gr_mem) ==
                {SLOTS[role] for role, value in observed_users.items() if value is not None},
                'Engine IPC group members differ from the original native accounts')
    require((missing and not any(observed_users.values())) or engine is not None,
            'original Engine IPC group is absent')
    return observed_users, observed_groups, engine


def provision(context, state):
    record = state['accounts']
    missing = record['established'] is False
    verify(record, missing=missing)
    # Visible rename is insufficient: every retry first re-establishes the original
    # receipt and its ancestor durability before any NSS mutation.
    context.save(state)
    context.sync(context.ROOT)
    users, groups, engine = verify(record, missing=missing)
    if engine is None:
        context.command('/usr/sbin/groupadd', '--system', '--gid', str(record['engine']), ENGINE)
    for role, name in SLOTS.items():
        users, groups, _ = verify(record, missing=missing)
        number = str(record[role])
        if groups[role] is None:
            context.command('/usr/sbin/groupadd', '--system', '--gid', number, name)
        users, _, _ = verify(record, missing=missing)
        if users[role] is None:
            context.command('/usr/sbin/useradd', '--system', '--uid', number, '--gid', number,
                            '--groups', ENGINE, '--no-create-home', '--home-dir', HOME + '/' + role,
                            '--shell', '/usr/sbin/nologin', name)
    verify(record)
    if not record['established']:
        record['established'] = True
        context.save(state)
    context.sync(context.ROOT)
    return {'accounts': 'original', 'engine_group': record['engine']}

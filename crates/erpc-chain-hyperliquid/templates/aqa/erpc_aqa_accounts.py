# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Once-only original AQA process identity; unknown or shared NSS identities refuse."""
import grp
import os
import pwd
from erpc_aqa_common import execute,fsync_dir,require
NATIVE="erpc-hl-aqa"
HOME="/nonexistent"


def account_plan(planned):
    require(isinstance(planned, dict) and set(planned) == {NATIVE}
            and all(isinstance(item, dict) and set(item) == {'uid', 'gid'}
                    and type(item['uid']) is int and type(item['gid']) is int
                    and 100 <= item['uid'] <= 999 and item['uid'] == item['gid']
                    for item in planned.values()), 'invalid dedicated identity reservation')

def account_snapshot():
    users, groups = pwd.getpwall(), grp.getgrall()
    require(len(users) <= 100000 and len(groups) <= 100000, 'account namespace exceeds its bound')
    return users, groups

def account_slot(name, chosen, missing=False):
    user, group = lookup(pwd.getpwnam, name), lookup(grp.getgrnam, name)
    users, groups = account_snapshot()
    named = [item for item in users if item.pw_name == name]
    named_groups = [item for item in groups if item.gr_name == name]
    def user_fields(value):
        return None if value is None else (value.pw_name,value.pw_uid,value.pw_gid,value.pw_dir,value.pw_shell)
    def group_fields(value):
        return None if value is None else (value.gr_name,value.gr_gid,frozenset(value.gr_mem))
    require(len(named) <= 1 and len(named_groups) <= 1
            and user_fields(user) == user_fields(named[0] if named else None)
            and user_fields(user) == user_fields(lookup(pwd.getpwuid, chosen['uid']))
            and group_fields(group) == group_fields(named_groups[0] if named_groups else None)
            and group_fields(group) == group_fields(lookup(grp.getgrgid, chosen['gid']))
            and not any((item.pw_uid == chosen['uid'] or item.pw_gid == chosen['gid'])
                        and item.pw_name != name for item in users)
            and not any(item.gr_gid == chosen['gid'] and item.gr_name != name for item in groups),
            'reserved identity differs across direct and enumerated NSS authority')
    if group is not None:
        require(group.gr_gid == chosen['gid'] and set(group.gr_mem) <= {name}, 'reserved group changed or is shared')
    if user is not None:
        require(group is not None and user.pw_uid == chosen['uid'] and user.pw_gid == chosen['gid']
                and user.pw_dir == str(HOME)
                and user.pw_shell == '/usr/sbin/nologin'
                and set(os.getgrouplist(name, chosen['gid'])) == {chosen['gid']},
                'dedicated service account differs from its original profile')
    require(missing or (user is not None and group is not None), 'original dedicated service identity is missing')
    return user, group

def accounts(expected):
    account_plan(expected)
    for name, chosen in expected.items(): account_slot(name, chosen)
    return expected

def lookup(function, value):
    try:
        return function(value)
    except KeyError:
        return None

def provision_accounts(state):
    """Durable numeric reservation precedes every fallible NSS mutation."""
    names = (NATIVE,)
    if (state.directory / 'accounts.json').exists():
        result = accounts(state.get('accounts.json'))
        require(state.get('account-reservation.json') == result,
                'completed identities differ from the original reservation')
        persist_accounts(state, result, completed=True)
        return result
    reservation = state.directory / 'account-reservation.json'
    if not reservation.exists():
        users, groups = account_snapshot()
        require(all(lookup(pwd.getpwnam, name) is None and lookup(grp.getgrnam, name) is None
                    for name in names) and not any(item.pw_name in names for item in users)
                and not any(item.gr_name in names for item in groups), 'unknown dedicated account cannot be adopted')
        used = {item.pw_uid for item in users} | {item.pw_gid for item in users} | {item.gr_gid for item in groups}
        available = [number for number in range(999, 99, -1)
                     if number not in used and lookup(pwd.getpwuid, number) is None and lookup(grp.getgrgid, number) is None]
        require(len(available) >= 1, 'one unused dedicated system identity are required')
        state.put('account-reservation.json', {name: {'uid': number, 'gid': number}
                                              for name, number in zip(names, available[:1])})
    planned = state.get('account-reservation.json')
    account_plan(planned)
    for name, chosen in planned.items(): account_slot(name, chosen, missing=True)
    # A visible rename after a failed directory fsync is not durable authority.
    # Re-establish that authority on every retry before changing any NSS entry.
    persist_accounts(state, planned)
    for name, home in ((NATIVE, str(HOME)),):
        chosen = planned[name]
        user, group = account_slot(name, chosen, missing=True)
        if group is None:
            execute(['/usr/sbin/groupadd', '--system', '--gid', str(chosen['gid']), name])
        user, _ = account_slot(name, chosen, missing=True)
        if user is None:
            execute(['/usr/sbin/useradd', '--system', '--uid', str(chosen['uid']), '--gid', str(chosen['gid']),
                     '--no-create-home', '--home-dir', home, '--shell', '/usr/sbin/nologin', name])
        account_slot(name, chosen)
    result = accounts(planned)
    state.put('accounts.json', result)
    persist_accounts(state, result, completed=True)
    return result

def persist_accounts(state, planned, completed=False):
    state.put('account-reservation.json', planned)
    if completed:
        state.put('accounts.json', planned)
    for directory in (state.directory, *state.directory.parents):
        fsync_dir(directory)

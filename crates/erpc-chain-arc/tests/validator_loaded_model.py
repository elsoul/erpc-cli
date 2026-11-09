#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert PID1 v255 get-property JSON model derived from generated unit text.

This test helper does not call the production policy parser to construct its
answers. Real PID1/NSS/credential grants remain deferred host acceptance.
"""
import json
import shlex
from types import SimpleNamespace

COMMANDS = ('ExecCondition', 'ExecStartPre', 'ExecStart', 'ExecStartPost', 'ExecReload', 'ExecStop', 'ExecStopPost')


def model(unit, text, guard=None):
    values = {}
    in_service = False
    for line in text.splitlines():
        if line.startswith('['): in_service = line == '[Service]'
        elif in_service and '=' in line and not line.startswith('#'):
            name, value = line.split('=', 1)
            values.setdefault(name, []).append(value)
    service = {}
    for name in ('User', 'Group', 'Type', 'WorkingDirectory', 'PAMName', 'RootDirectory', 'RootImage'):
        service[name] = {'type': 's', 'data': values.get(name, [''])[0]}
    for name in ('PrivateUsers', 'DynamicUser'):
        service[name] = {'type': 'b', 'data': False}
    for name in ('SupplementaryGroups', 'Environment'):
        service[name] = {'type': 'as', 'data': [word for value in values.get(name, []) for word in shlex.split(value)]}
    for name, signature in [('LoadCredentialEncrypted', 'a(ss)'), ('LoadCredential', 'a(ss)'),
                             ('SetCredential', 'a(say)'), ('SetCredentialEncrypted', 'a(say)'),
                             ('ImportCredential', 'as'), ('EnvironmentFiles', 'a(sb)'),
                             ('PassEnvironment', 'as'), ('UnsetEnvironment', 'as'), ('BindPaths', 'a(ssbt)'),
                             ('BindReadOnlyPaths', 'a(ssbt)'), ('TemporaryFileSystem', 'a(ss)'), ('MountImages', 'a(ssba(ss))')]:
        service[name] = {'type': signature, 'data': [value.split(':', 1) for value in values.get(name, [])]}
    for name in COMMANDS:
        raw = list(values.get(name, []))
        if name == 'ExecStartPre' and guard:
            raw += [line.split('=', 1)[1] for line in guard.splitlines() if line.startswith('ExecStartPre=')]
        rows = []
        for value in raw:
            privileged = value[0] == '+'
            args = shlex.split(value[1:] if privileged else value)
            rows.append([args[0], args, ['privileged'] if privileged else [], 0, 0, 0, 0, 0, 0, 0])
        service[name + 'Ex'] = {'type': 'a(sasasttttuii)', 'data': rows}
    dropins = ['/etc/systemd/system/' + unit + '.d/50-erpc-firewall-guard.conf'] if guard else []
    own = {name: {'type': 's', 'data': value} for name, value in
           [('Id', unit), ('LoadState', 'loaded'), ('FragmentPath', '/etc/systemd/system/' + unit)]}
    own.update({name: {'type': 'as', 'data': value} for name, value in
                [('DropInPaths', dropins), ('OnFailure', []), ('OnSuccess', [])]})
    return {'Service': service, 'Unit': own}


def reply(args, records):
    assert args[:6] == ('/usr/bin/busctl', '--system', '--no-pager', '--json=short', '--timeout=10s', 'get-property')
    interface = args[8].rsplit('.', 1)[1]
    path = args[7]
    for unit, record in records.items():
        escaped = ''.join(character if character.isascii() and character.isalnum() else '_' + format(ord(character), '02x')
                          for character in unit)
        if path.endswith('/' + escaped):
            return SimpleNamespace(returncode=0, stdout=('\n'.join(json.dumps(record[interface][name]) for name in args[9:]) + '\n').encode(), stderr=b'')
    raise AssertionError('unknown original service path')

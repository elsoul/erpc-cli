#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Authenticate PID1's effective service policy before credentials or hooks.

systemd v255 busctl get-property emits typed {type,data} JSON values in requested
order; Exec*Ex exposes executable, argv and command flags, not only display text.
Only selected properties are requested. Values are never printed or persisted.
"""
import json
import shlex
from arc_files import require, strict_json

EXEC = ('ExecCondition', 'ExecStartPre', 'ExecStart', 'ExecStartPost', 'ExecReload', 'ExecStop', 'ExecStopPost')
SERVICE = {'User': 's', 'Group': 's', 'SupplementaryGroups': 'as', 'DynamicUser': 'b',
           'PrivateUsers': 'b', 'PAMName': 's', 'RootDirectory': 's', 'RootImage': 's',
           'Type': 's', 'WorkingDirectory': 's', 'Environment': 'as', 'EnvironmentFiles': 'a(sb)',
           'PassEnvironment': 'as', 'UnsetEnvironment': 'as', 'BindPaths': 'a(ssbt)',
           'BindReadOnlyPaths': 'a(ssbt)', 'TemporaryFileSystem': 'a(ss)', 'MountImages': 'a(ssba(ss))',
           'LoadCredential': 'a(ss)', 'LoadCredentialEncrypted': 'a(ss)',
           'SetCredential': 'a(say)', 'SetCredentialEncrypted': 'a(say)', 'ImportCredential': 'as',
           **{name + 'Ex': 'a(sasasttttuii)' for name in EXEC}}
UNIT = {'Id': 's', 'LoadState': 's', 'FragmentPath': 's', 'DropInPaths': 'as', 'OnFailure': 'as', 'OnSuccess': 'as'}


def object_path(unit):
    return '/org/freedesktop/systemd1/unit/' + ''.join(
        char if char.isascii() and char.isalnum() else '_' + format(ord(char), '02x') for char in unit)


def properties(context, unit, interface, schema):
    result = context.command('/usr/bin/busctl', '--system', '--no-pager', '--json=short', '--timeout=10s', 'get-property',
        'org.freedesktop.systemd1', object_path(unit), 'org.freedesktop.systemd1.' + interface,
        *schema, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 1048576, 'loaded service policy is unavailable')
    raw = result.stdout.decode('utf-8')
    decoder, values = json.JSONDecoder(), []
    while raw.strip():
        raw = raw.lstrip()
        _, end = decoder.raw_decode(raw)
        values.append(strict_json(raw[:end]))
        require(len(values) <= len(schema), 'unexpected loaded policy response')
        raw = raw[end:]
    require(len(values) == len(schema), 'incomplete loaded policy response')
    answer = {}
    for (name, signature), value in zip(schema.items(), values):
        require(isinstance(value, dict) and set(value) == {'type', 'data'} and value['type'] == signature,
                'loaded policy has an unexpected D-Bus type')
        answer[name] = value['data']
    return answer


def service_lines(text):
    section, values = None, {}
    for line in text.splitlines():
        if line.startswith('['):
            section = line
        elif section == '[Service]' and line and not line.startswith('#'):
            name, separator, value = line.partition('=')
            require(separator, 'invalid original service receipt')
            values.setdefault(name, []).append(value)
    return values


def command(value):
    privileged = value.startswith('+')
    args = shlex.split(value[1:] if privileged else value)
    require(args and args[0].startswith('/'), 'invalid original executable receipt')
    return [args[0], args, ['privileged'] if privileged else []]


def commands(value):
    require(isinstance(value, list) and len(value) <= 16, 'invalid loaded command list')
    result = []
    for row in value:
        require(isinstance(row, list) and len(row) == 10 and isinstance(row[0], str) and
                isinstance(row[1], list) and all(isinstance(arg, str) for arg in row[1]) and
                isinstance(row[2], list) and all(isinstance(flag, str) for flag in row[2]) and
                all(type(number) is int for number in row[3:]), 'invalid loaded command structure')
        result.append(row[:3])
    return result


def proof(context, state, receipt, unit, firewall=False):
    original = service_lines(receipt['text'])
    guard = ''
    expected_dropins = []
    if not firewall:
        guard_path = '/etc/systemd/system/' + unit + '.d/50-erpc-firewall-guard.conf'
        guard = context.firewall_guard_config()
        require(context.read(guard_path) == guard.encode(), 'original firewall drop-in differs')
        expected_dropins = [guard_path]
    loaded_unit = properties(context, unit, 'Unit', UNIT)
    require(loaded_unit == {'Id': unit, 'LoadState': 'loaded',
                           'FragmentPath': '/etc/systemd/system/' + unit, 'DropInPaths': expected_dropins,
                           'OnFailure': [], 'OnSuccess': []},
            'loaded fragment or drop-in policy differs from the original service')
    values = properties(context, unit, 'Service', SERVICE)
    for field in ('User', 'Group', 'Type', 'WorkingDirectory'):
        require(values[field] == original.get(field, [''])[0], 'loaded numeric recipient or service type differs')
    require(values['DynamicUser'] is False and values['PrivateUsers'] is False and
            all(values[field] == '' for field in ('PAMName', 'RootDirectory', 'RootImage')),
            'loaded execution identity or root namespace was replaced')
    require(isinstance(values['SupplementaryGroups'], list) and
            sorted(values['SupplementaryGroups']) == sorted(original.get('SupplementaryGroups', [''])[0].split()),
            'loaded supplementary groups differ')
    expected_environment = [value for line in original.get('Environment', []) for value in shlex.split(line)]
    require(values['Environment'] == expected_environment and values['EnvironmentFiles'] == [],
            'loaded native environment differs')
    require(all(values[field] == [] for field in ('PassEnvironment', 'UnsetEnvironment', 'BindPaths',
                'BindReadOnlyPaths', 'TemporaryFileSystem', 'MountImages')), 'loaded namespace or environment injection differs')
    expected_credentials = [value.split(':', 1) for value in original.get('LoadCredentialEncrypted', [])]
    require(values['LoadCredentialEncrypted'] == expected_credentials and
            all(values[field] == [] for field in ('LoadCredential', 'SetCredential', 'SetCredentialEncrypted', 'ImportCredential')),
            'loaded credential names, sources or additions differ')
    for name in EXEC:
        expected = [command(value) for value in original.get(name, [])]
        if name == 'ExecStartPre':
            expected += [command(value) for value in service_lines(guard).get(name, [])]
        require(commands(values[name + 'Ex']) == expected, 'loaded executable commands or flags differ')
    # Re-read the fragment provenance after inspecting the service properties.
    require(properties(context, unit, 'Unit', UNIT) == loaded_unit,
            'loaded service provenance changed during verification')
    return receipt

#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original listener/IPC generations and bounded, fixed read-only Arc RPC observations."""
import http.client
import json
import os
import re
import socket
import stat
import time
import urllib.request
from arc_files import Refused, encoded, require, strict_json
import arc_process as process
import arc_protocol as protocol
import arc_storage as storage
import arc_custody as custody
import arc_release as release


class Pending(Refused):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Refused('Arc observation redirects are refused')


def sockets(c, record):
    result = set()
    root = c.path('/proc') / str(record['pid']) / 'fd'
    for path in root.iterdir():
        try:
            target = os.readlink(path)
        except FileNotFoundError:
            continue
        match = re.fullmatch(r'socket:\[([0-9]+)\]', target)
        if match:
            result.add(match.group(1))
    return result


def ipc(c, state):
    before = process.running(c, state, 'execution', state['runtime'])
    owned = sockets(c, before)
    entries = (c.path('/proc/net/unix')).read_text().splitlines()[1:]
    for name in ('reth.ipc', 'auth.ipc'):
        path = c.path('/run/arc') / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            raise Pending('original Arc IPC is not yet available') from None
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == state['service_uid'] and
                info.st_gid == state['service_gid'] and not info.st_mode & 0o007,
                'Arc IPC path belongs to another identity or is public')
        matches = [line.split() for line in entries if len(line.split()) >= 8 and line.split()[7] == str(path)]
        require(len(matches) == 1 and matches[0][6] in owned,
                'Arc execution IPC is not held by the original execution generation')
    after = process.running(c, state, 'execution', state['runtime'])
    require(before == after, 'Arc execution changed during IPC qualification')
    return before


def listeners(c, state, component):
    before = process.running(c, state, component, state['runtime'])
    owned = sockets(c, before)
    required = {8545: bool(state['policy']['rpc_allow']), 8546: bool(state['policy']['rpc_allow']),
                9001: bool(state['policy']['monitoring_allow'])} if component == 'execution' else {
                    31000: False, 29000: bool(state['policy']['monitoring_allow'])}
    rows = []
    for name in ('tcp', 'tcp6'):
        try:
            lines = c.path('/proc/net/' + name).read_text().splitlines()[1:]
        except FileNotFoundError:
            require(name == 'tcp6', 'Arc IPv4 socket inventory is unavailable')
            continue
        for line in lines:
            fields = line.split()
            require(len(fields) >= 10, 'Arc kernel socket observation is incomplete')
            if fields[3] != '0A':
                continue
            address, port = fields[1].split(':')
            rows.append((int(port, 16), address, fields[7], fields[9]))
    for port, public in required.items():
        matches = [row for row in rows if row[0] == port]
        allowed = {'00000000'} if public else {'0100007F'}
        require(len(matches) == 1 and matches[0][1] in allowed and
                matches[0][2] == str(state['service_uid']) and matches[0][3] in owned,
                'Arc fixed listener is not exclusively held by its original process')
    require(process.running(c, state, component, state['runtime']) == before,
            'Arc process changed during listener qualification')
    return before


def rpc(url, method, params):
    allowed = {'arc_getVersion', 'eth_chainId', 'eth_getBlockByNumber', 'eth_syncing', 'eth_blockNumber'}
    require(method in allowed, 'unexpected Arc observation method')
    body = encoded({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params})
    request = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'}, method='POST')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=5) as response:
        require(response.status == 200, 'Arc RPC observation failed')
        limit = 8 * 1024 * 1024 if method == 'eth_getBlockByNumber' else 65536
        raw = response.read(limit + 1)
        require(len(raw) <= limit, 'Arc RPC observation exceeds its bound')
    value = strict_json(raw)
    require(isinstance(value, dict) and value.get('jsonrpc') == '2.0' and type(value.get('id')) is int and value['id'] == 1
            and set(value) == {'jsonrpc', 'id', 'result'}, 'invalid Arc RPC observation')
    return value


def report(c, state):
    values = {'observed_unix': str(int(time.time())), 'original_authority': 'no',
              'execution_authority': 'no', 'consensus_authority': 'no', 'credential': 'no', 'snapshot': 'done' if state.get('bootstrap_complete') else 'missing'}
    for component, unit in process.UNITS.items():
        try:
            values['unit_' + unit.removesuffix('.service')] = process.properties(c, unit)['ActiveState']
        except Exception:
            values['unit_' + unit.removesuffix('.service')] = 'unknown'
    try:
        values['unit_erpc-arc-firewall'] = process.properties(c, 'erpc-arc-firewall.service')['ActiveState']
    except Exception:
        values['unit_erpc-arc-firewall'] = 'unknown'
    try:
        c.common().guard()
        values['firewall_table'] = 'yes'
    except Exception:
        values['firewall_table'] = 'no'
    for file, key in [('pending.json', 'firewall_armed'), ('startup-revoked', 'firewall_revoked')]:
        values[key] = 'yes' if c.path('/etc/erpc/arc/' + file).exists() else 'no'
    try:
        custody.verify(c, state)
        values['credential'] = 'yes'
    except Exception:
        pass
    try:
        home = storage.verify(c, state)
        fs = os.statvfs(home)
        values['data_free_kb'] = str(fs.f_bavail * fs.f_frsize // 1024)
        values['data_used_kb'] = str((fs.f_blocks - fs.f_bfree) * fs.f_frsize // 1024)
    except Exception:
        pass
    if isinstance(state.get('source'), dict):
        values['current'] = release.directory(state['source'])
        values['source_archive'] = state['source']['archive_sha256']
        values['source_platform'] = state['source']['platform']
    try:
        # Read-only eligibility: no seed decryption, NSS creation or custody publication.
        c.eligible(state, credential=False)
        before = listeners(c, state, 'execution')
        ipc(c, state)
        values['execution_authority'] = 'yes'
        original_consensus = None
        try:
            original_consensus = listeners(c, state, 'consensus')
        except Exception:
            pass
        for name, method, params in (
            ('version_info', 'arc_getVersion', []), ('chain_id', 'eth_chainId', []),
            ('genesis', 'eth_getBlockByNumber', ['0x0', False]),
            ('latest_block', 'eth_getBlockByNumber', ['latest', False]), ('syncing', 'eth_syncing', []),
        ):
            value = rpc('http://127.0.0.1:8545', method, params)
            if name == 'latest_block' and isinstance(value['result'], dict):
                value['result'] = {key: value['result'].get(key) for key in ('hash', 'number', 'timestamp')}
            values[name] = json.dumps(value, separators=(',', ':'))
        version = strict_json(values['version_info'])['result']
        chain = strict_json(values['chain_id'])['result']
        genesis = strict_json(values['genesis'])['result']
        require(isinstance(version, dict) and version.get('git_commit') == state['source']['commit'] and
                version.get('cargo_version') == state['source']['version'] + ' (' + state['source']['commit'][:8] + ')' and
                isinstance(chain, str) and re.fullmatch(r'0x[0-9a-fA-F]+', chain) and
                int(chain, 16) == state['contract']['chain_id'] and isinstance(genesis, dict) and
                genesis.get('hash') == state['contract']['genesis_hash'],
                'Arc native API does not match the original source/network/genesis')
        require(listeners(c, state, 'execution') == before, 'Arc execution generation changed during RPC read')
        if original_consensus is not None:
            require(listeners(c, state, 'consensus') == original_consensus, 'Arc consensus generation changed during RPC read')
            values['consensus_authority'] = 'yes'
            values['original_authority'] = 'yes'
    except Exception:
        # Never accept spoofed loopback data when original process qualification fails.
        values['execution_authority'] = 'no'
        values['consensus_authority'] = 'no'
        for key in ('version_info', 'chain_id', 'genesis', 'latest_block', 'syncing'):
            values.pop(key, None)
    try:
        require(values['execution_authority'] == 'yes', 'local Arc execution is not qualified')
        values['public_head'] = json.dumps(rpc(protocol.NETWORKS[state['contract']['network']]['public_rpc'],
                                               'eth_blockNumber', []), separators=(',', ':'))
    except Exception:
        pass
    return {'observation': '\n'.join(key + '=' + value for key, value in values.items()) + '\n',
            'phase': state['phase'], 'generation': state['generation'],
            'bootstrap_intent': state.get('bootstrap_intent'),
            'credential_recoverable': isinstance(state.get('credential'), dict)}

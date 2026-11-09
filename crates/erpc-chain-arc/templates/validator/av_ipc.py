#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""No request bytes before original native EL process/Unix peer authentication."""
import json
import os
import socket
import stat
import struct

from arc_files import require, strict_json
import av_accounts
import av_process
from av_units import ENGINE_RUN


def namespace(context, state):
    context.protected('/run', directory=True)
    root = context.path(ENGINE_RUN)
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == state['accounts']['execution'] and
            info.st_gid == state['accounts']['engine'] and stat.S_IMODE(info.st_mode) == 0o710,
            'original Engine IPC directory ownership or exclusive traversal changed')
    require(set(os.listdir(root)) <= {'reth.ipc', 'auth.ipc'}, 'unknown Engine IPC directory contents')
    return root, info


def response(stream):
    raw = bytearray()
    decoder = json.JSONDecoder()
    while len(raw) <= 8 * 1024 * 1024:
        block = stream.recv(min(65536, 8 * 1024 * 1024 + 1 - len(raw)))
        require(block, 'native execution IPC closed before a complete response')
        raw.extend(block)
        require(len(raw) <= 8 * 1024 * 1024, 'native execution IPC response exceeds the bound')
        try:
            text = raw.decode('utf-8')
            _, end = decoder.raw_decode(text.lstrip())
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        stripped = text.lstrip()
        require(not stripped[end:].strip(), 'native execution returned multiple IPC results')
        value = strict_json(stripped)
        require(isinstance(value, dict) and value.get('jsonrpc') == '2.0' and
                type(value.get('id')) is int and value['id'] == 1 and
                'result' in value and 'error' not in value, 'native execution IPC query failed')
        return value['result']
    require(False, 'native execution IPC response exceeds the bound')


def call(context, state, method, params):
    require(method in ('eth_chainId', 'eth_getBlockByNumber', 'eth_syncing', 'eth_call') and isinstance(params, list),
            'validator IPC observer only accepts its read-only qualification methods')
    av_accounts.verify(state['accounts'])
    runtime = state['runtime']
    before = av_process.running(context, state, 'execution', runtime)
    root, directory = namespace(context, state)
    target = root / 'reth.ipc'
    info = target.lstat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == state['accounts']['execution'] and
            info.st_gid == state['accounts']['engine'] and not info.st_mode & 0o007,
            'original execution IPC socket authority changed')
    require(hasattr(socket, 'SO_PEERCRED'), 'native validator IPC requires Linux peer credentials')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(10)
        connection.connect(str(target))
        peer = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
        require(peer == (before['pid'], state['accounts']['execution'], state['accounts']['engine']),
                'connected execution socket is not the original native process')
        require(av_process.running(context, state, 'execution', runtime) == before and
                (root.lstat().st_dev, root.lstat().st_ino) == (directory.st_dev, directory.st_ino) and
                (target.lstat().st_dev, target.lstat().st_ino) == (info.st_dev, info.st_ino),
                'execution IPC authority changed before the request')
        payload = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params},
                             separators=(',', ':'), allow_nan=False).encode()
        require(len(payload) <= 16384, 'native execution IPC request exceeds the bound')
        connection.sendall(payload + b'\n')
        result = response(connection)
        require(av_process.running(context, state, 'execution', runtime) == before,
                'original execution process changed during the read-only observation')
        return result

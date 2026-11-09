#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Closed original Arc follower identity and current public deployment policy."""
import base64
import ipaddress
import json
import pathlib
import re
from arc_files import require

NETWORKS = json.loads(pathlib.Path(__file__).with_name('networks.json').read_text())['networks']


def contract(value):
    fields = {'owner', 'network', 'chain_id', 'genesis_hash', 'public_key', 'rpc_type', 'host_key_sha256'}
    require(isinstance(value, dict) and set(value) == fields, 'invalid original Arc contract')
    require(isinstance(value['owner'], str) and re.fullmatch('[a-z0-9]{26}', value['owner']),
            'original Arc inventory identifier is required')
    require(value['network'] in NETWORKS and type(value['chain_id']) is int and
            value['chain_id'] == NETWORKS[value['network']]['chain_id'] and
            value['genesis_hash'] == NETWORKS[value['network']]['genesis_hash'],
            'original Arc network or genesis differs')
    require(value['rpc_type'] in ('full', 'archive', 'provider') and
            isinstance(value['host_key_sha256'], str) and
            re.fullmatch('[0-9a-f]{64}', value['host_key_sha256']), 'invalid Arc host or history contract')
    raw = base64.b64decode(value['public_key'], validate=True)
    require(len(raw) == 32 and base64.b64encode(raw).decode() == value['public_key'],
            'invalid original Arc public key')
    return value


def policy(value, original):
    fields = {'rpc_allow', 'monitoring_allow', 'management_allow', 'ssh_port', 'debug_api',
              'trusted_peers', 'sentry_peers'}
    require(isinstance(value, dict) and set(value) == fields, 'invalid Arc deployment policy')
    require(type(value['ssh_port']) is int and 0 < value['ssh_port'] <= 65535 and
            type(value['debug_api']) is bool, 'invalid observed SSH port or RPC namespace policy')
    require(not (original['rpc_type'] == 'provider' and value['debug_api']),
            'Arc provider mode does not expose debug or trace')
    for name in ('rpc_allow', 'monitoring_allow', 'management_allow'):
        rows = value[name]
        require(isinstance(rows, list) and len(rows) <= 128 and len(rows) == len(set(rows)),
                'invalid Arc ingress list')
        for row in rows:
            network = ipaddress.ip_network(row, strict=True)
            require(network.version == 4 and (name == 'rpc_allow' or network.prefixlen > 0),
                    'unsupported Arc ingress prefix')
    for name in ('trusted_peers', 'sentry_peers'):
        require(isinstance(value[name], list) and len(value[name]) <= 128 and
                all(isinstance(row, str) and len(row) <= 512 for row in value[name]),
                'invalid Arc provider peers')
    if original['rpc_type'] == 'provider':
        require(value['trusted_peers'] and value['sentry_peers'], 'onboarded Arc provider peers are required')
    else:
        require(not value['trusted_peers'] and not value['sentry_peers'],
                'Arc follower profile does not accept provider peers')
    for peer in value['trusted_peers']:
        match = re.fullmatch(r'enode://[0-9a-fA-F]{128}@([0-9.]+):([0-9]{1,5})', peer)
        require(match is not None and 0 < int(match.group(2)) <= 65535, 'invalid Arc execution peer')
        ipaddress.IPv4Address(match.group(1))
    for peer in value['sentry_peers']:
        match = re.fullmatch(r'/ip4/([0-9.]+)/tcp/([0-9]{1,5})/p2p/[A-Za-z0-9]+', peer)
        require(match is not None and 0 < int(match.group(2)) <= 65535, 'invalid Arc consensus peer')
        ipaddress.IPv4Address(match.group(1))
    return value

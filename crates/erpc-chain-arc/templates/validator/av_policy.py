#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Closed operator-approved peer/fee configuration and bounded ingress."""
import ipaddress
import re

from arc_files import require


def address(value):
    return isinstance(value, str) and re.fullmatch('0x[0-9a-f]{40}', value) and int(value[2:], 16) > 0


def peer_ip(value):
    result = ipaddress.ip_address(value)
    require(not (result.is_unspecified or result.is_multicast or result.is_loopback),
            'approved peer must be a unicast remote address')
    return result


def execution_peer(value):
    match = re.fullmatch(r'enode://([0-9a-f]{128})@(\[[0-9a-f:]+\]|[0-9.]+):([1-9][0-9]{0,4})', value)
    require(match is not None and int(match[1], 16) > 0 and int(match[3]) <= 65535,
            'invalid approved Arc execution peer')
    peer_ip(match[2].strip('[]'))


def sentry_peer(value):
    parts = value.split('/')
    require(len(parts) == 7 and parts[0] == '' and parts[1] in ('ip4', 'ip6') and
            parts[3] == 'tcp' and parts[5] == 'p2p' and
            re.fullmatch('[1-9][0-9]{0,4}', parts[4]) and int(parts[4]) <= 65535 and
            re.fullmatch('[1-9A-HJ-NP-Za-km-z]{16,128}', parts[6]), 'invalid approved Arc sentry peer')
    ip = peer_ip(parts[2])
    require(ip.version == (4 if parts[1] == 'ip4' else 6), 'approved sentry address family differs')


def validate(state, value):
    require(isinstance(value, dict) and set(value) == {'approved', 'fee_recipient', 'execution_peers',
                                                      'sentry_peers', 'phase', 'ssh_port',
                                                      'management_allow', 'monitoring_allow'},
            'invalid Arc validator policy fields')
    require(type(value['approved']) is bool and address(value['fee_recipient']) and
            type(value['ssh_port']) is int and 1 <= value['ssh_port'] <= 65535,
            'invalid Arc validator approval, recipient or observed SSH port')
    require(value['phase'] in ('observer', 'validator'), 'unknown Arc participation phase')
    require(not state.get('signer_used'),
            'a used consensus signer requires qualified production recovery; observer fallback is refused')
    for field in ('execution_peers', 'sentry_peers', 'management_allow', 'monitoring_allow'):
        rows = value[field]
        require(isinstance(rows, list) and len(rows) <= 128 and
                all(isinstance(row, str) and len(row) <= 512 for row in rows) and len(set(rows)) == len(rows),
                'invalid Arc validator peer or ingress list')
        for row in rows:
            if field == 'execution_peers':
                execution_peer(row)
            elif field == 'sentry_peers':
                sentry_peer(row)
            else:
                network = ipaddress.ip_network(row, strict=True)
                require(network.version == 4 and network.prefixlen > 0 and str(network) == row,
                        'Arc validator ingress requires a canonical restricted IPv4 network')
    if value['phase'] == 'validator':
        require(value['approved'] and value['execution_peers'] and value['sentry_peers'],
                'institutional approval and explicit execution/consensus sentries are required')
    return value

# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Bounded local observations. Network anchors come from protected installation metadata."""
import json
import re
import time
import urllib.request


def rpc(port, method, params):
    request = urllib.request.Request('http://127.0.0.1:' + str(port),
        data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
        headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                return None
        result = json.loads(raw)
        if result.get('jsonrpc') != '2.0' or result.get('id') != 1 or 'error' in result:
            return None
        return result.get('result')
    except Exception:
        return None


def integer(value):
    return value if type(value) is int and 0 <= value < 2 ** 64 else None


def quantity(value):
    if not isinstance(value, str) or not re.fullmatch('0x[0-9a-fA-F]{1,16}', value):
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def execution_synced(value, latest):
    if value is False:
        return True
    if not isinstance(value, dict):
        return False
    current, highest, start = [quantity(value.get(key)) for key in ('currentBlock', 'highestBlock', 'startingBlock')]
    head = quantity(latest.get('number')) if isinstance(latest, dict) else None
    if (current is None or highest is None or start is None or head is None
            or start > current or current < highest or abs(current - head) > 128):
        return False
    stages = value.get('stages')
    if not isinstance(stages, list) or not stages:
        return False
    checkpoints = {}
    for stage in stages:
        if not isinstance(stage, dict) or not isinstance(stage.get('name'), str) or stage['name'] in checkpoints:
            return False
        block = quantity(stage.get('block'))
        if block is None:
            return False
        checkpoints[stage['name']] = block
    # Pinned Reth reports highestBlock=currentBlock even during pipeline work.
    # Require execution/finish evidence too. Recent engine blocks may be ahead
    # of persisted checkpoints; current CL/finality/L1 checks remain mandatory.
    return all(name in checkpoints and current - 1024 <= checkpoints[name] <= current
               for name in ('Execution', 'Finish'))


def evaluate(observed, expected, services, now, gateway=True):
    problems = []
    required = ['execution', 'consensus', 'upstreams'] + (['rpc'] if gateway else [])
    if any(services.get(role) != 'active' for role in required):
        problems.append('one or more follower services are not active')
    if quantity(observed.get('chain_id')) != expected['chain_id']:
        problems.append('execution chain identity unavailable or mismatched')
    if not execution_synced(observed.get('syncing'), observed.get('latest')):
        problems.append('execution synchronization has not completed')
    rollup = observed.get('rollup')
    genesis = rollup.get('genesis', {}).get('l2') if isinstance(rollup, dict) else None
    if (not isinstance(rollup, dict) or integer(rollup.get('l2_chain_id')) != expected['chain_id']
            or integer(rollup.get('l1_chain_id')) != expected['l1_chain_id']
            or not isinstance(genesis, dict) or integer(genesis.get('number')) != expected['anchor']['number']
            or genesis.get('hash') != expected['anchor']['hash']):
        problems.append('consensus rollup/L1 identity or genesis anchor mismatched')
    latest = observed.get('latest')
    head = quantity(latest.get('number')) if isinstance(latest, dict) else None
    timestamp = quantity(latest.get('timestamp')) if isinstance(latest, dict) else None
    if timestamp is None or timestamp > now + 60 or now - timestamp > 300:
        problems.append('execution tip is stale, unavailable or implausibly future')
    sync = observed.get('consensus_sync')
    sync = sync if isinstance(sync, dict) else {}
    refs = [sync.get(key) for key in ('unsafe_l2', 'safe_l2', 'finalized_l2')]
    numbers = [integer(ref.get('number')) if isinstance(ref, dict) else None for ref in refs]
    if (any(number is None for number in numbers) or not all(numbers)
            or not numbers[0] >= numbers[1] >= numbers[2]
            or head is None or not numbers[0] - 3 <= head <= numbers[0] + 100):
        problems.append('unsafe/safe/finalized L2 heads are missing, inconsistent or not caught up')
    else:
        for index, label in [(1, 'safe'), (2, 'finalized')]:
            stamp = integer(refs[index].get('timestamp'))
            maximum_age = 3600 if label == 'safe' else 7200
            if stamp is None or stamp > now + 60 or now - stamp > maximum_age:
                problems.append('consensus ' + label + ' L2 head is stale or has no valid timestamp')
            canonical = observed.get('canonical_' + label)
            if (not isinstance(canonical, dict) or not isinstance(refs[index].get('hash'), str)
                    or not re.fullmatch('0x[a-fA-F0-9]{64}', refs[index]['hash'])
                    or canonical.get('hash') != refs[index]['hash']):
                problems.append('execution canonical ' + label + ' head differs from consensus')
    l1 = sync.get('current_l1')
    l1_number = integer(l1.get('number')) if isinstance(l1, dict) else None
    l1_timestamp = integer(l1.get('timestamp')) if isinstance(l1, dict) else None
    l1_head = quantity(observed.get('l1_head'))
    if (l1_number in (None, 0) or l1_head is None or not l1_head - 128 <= l1_number <= l1_head
            or l1_timestamp is None or l1_timestamp > now + 60 or now - l1_timestamp > 1800):
        problems.append('L1 derivation has not caught up with the verified upstream')
    if quantity(observed.get('l1_chain_id')) != expected['l1_chain_id']:
        problems.append('verified L1 upstream transport is unavailable')
    return {'ready': not problems, 'problems': problems}


def inspect(state, expected, services, gateway=True):
    observed = {
        'chain_id': rpc(8545, 'eth_chainId', []),
        'syncing': rpc(8545, 'eth_syncing', []),
        'latest': rpc(8545, 'eth_getBlockByNumber', ['latest', False]),
        'execution_version': rpc(8545, 'web3_clientVersion', []),
        'execution_peers': rpc(8545, 'net_peerCount', []),
        'rollup': rpc(9545, 'optimism_rollupConfig', []),
        'consensus_sync': rpc(9545, 'optimism_syncStatus', []),
        'consensus_version': rpc(9545, 'optimism_version', []),
        'l1_chain_id': rpc(18545, 'eth_chainId', []),
        'l1_head': rpc(18545, 'eth_blockNumber', []),
    }
    sync = observed['consensus_sync']
    if isinstance(sync, dict):
        for label in ('safe', 'finalized'):
            ref = sync.get(label + '_l2')
            height = integer(ref.get('number')) if isinstance(ref, dict) else None
            if height is not None:
                observed['canonical_' + label] = rpc(8545, 'eth_getBlockByNumber', [hex(height), False])
    health = evaluate(observed, expected, services, int(time.time()), gateway)
    if state['phase'] != 'installed' or not state.get('bootstrap_done'):
        health['ready'] = False
        health['problems'].insert(0, 'installation or bootstrap is incomplete or retired')
    return {'phase': state['phase'], 'contract': state['contract'], 'pair': state.get('pair'), 'target': state.get('target'),
            'bootstrap_done': state.get('bootstrap_done', False),
            'services': services, 'observations': observed, 'readiness': health}

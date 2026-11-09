#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Bounded official private REST observations; no inferred admission or vote success."""
import base64

from arc_files import require
import av_admission
import av_process
import av_events


def uint(value):
    return type(value) is int and 0 <= value < 2**64


def status(context, state):
    problems = []
    result = {'chain': 'arc', 'role': 'validator', 'network': state['contract']['network'],
              'mode': state.get('policy', {}).get('phase'), 'ready': False, 'validator_ready': False,
              'phase': state['phase'], 'retired': context.is_retired(), 'observations': {},
              'bootstrap_intent': state.get('bootstrap_intent'),
              'operation_intent': state.get('generation'),
              'bootstrap_complete': state.get('bootstrap_complete', False),
              'production_activation_available': False,
              'operation_cancelled': context.operation_cancelled(state), 'bootstrap_failed': False,
              'lifecycle_recovery_required': av_events.needs_recovery(context, state)}
    if state['phase'] == 'bootstrap':
        try:
            context.unit_proof(state, 'bootstrap')
            native = av_process.properties(context, av_process.UNITS['bootstrap'])
            result['bootstrap_failed'] = (native.get('Result') not in ('success', '', None) or
                                          native.get('ExecMainStatus') not in ('0', '', None))
        except Exception:
            result['bootstrap_observation'] = 'unavailable'
    try:
        context.verify_original(state)
        runtime = state['runtime']
        for component in ('execution', 'consensus'):
            av_process.running(context, state, component, runtime)
        result['running'] = True
    except Exception:
        result['running'] = False
        result['problems'] = ['original native runtime or authority is unavailable']
        return result
    try:
        head = av_admission.execution_head(context, state)
        result['observations']['execution'] = {'block_hash': head['hash'],
                                               'block_number': av_admission.quantity(head['number'])}
    except Exception:
        problems.append('original execution chain, genesis or fresh synchronized head could not be qualified')
    try:
        admission = av_admission.observe(context, state)
        result['observations']['admission'] = admission
    except Exception:
        admission = None
        if result['mode'] == 'validator':
            problems.append('original controller admission could not be qualified')
    try:
        version = context.private_rest(state, '/version')
        require(isinstance(version, dict) and version.get('git_commit') == state['source']['commit'] and
                version.get('cargo_version') == state['source']['version'].removeprefix('v'),
                'private consensus source differs')
        observed = context.private_rest(state, '/status')
        network = context.private_rest(state, '/network-state')
        require(isinstance(observed, dict) and uint(observed.get('height')) and
                uint(observed.get('db_latest_height')) and observed['height'] > 0 and
                observed['sync_state'] in ('InSync', 'CatchingUp') and isinstance(network, dict),
                'private consensus status is incomplete')
        result['observations']['consensus'] = {'height': observed['height'],
            'db_latest_height': observed['db_latest_height'], 'sync_state': observed['sync_state'],
            'source': version['git_commit']}
        if observed['sync_state'] != 'InSync':
            problems.append('native consensus is catching up')
        ready = context.private_ready(state)
        require(type(ready) is bool, 'native readiness probe is unavailable')
        if not ready:
            problems.append('native readiness probe is not ready')
        if result['mode'] == 'validator':
            public = '0x' + base64.b64decode(state['contract']['public_key'], validate=True).hex()
            require(observed.get('public_key') == public and
                    network.get('local_node', {}).get('is_validator') is True and
                    network['local_node'].get('persistent_peers_only') is True,
                    'native consensus is not the original admitted validator profile')
            validators = observed.get('validator_set', {}).get('validators')
            require(isinstance(validators, list) and len(validators) <= 10000,
                    'native consensus validator set is unavailable')
            original = [value for value in validators if isinstance(value, dict) and value.get('public_key_hex') == public]
            require(len(original) == 1 and uint(original[0].get('voting_power')) and
                    original[0]['voting_power'] > 0, 'original consensus key has no native effective voting power')
            if admission is None or not admission['admitted']:
                problems.append('original validator is not actively admitted on the qualified execution head')
            elif admission['voting_power'] != original[0]['voting_power']:
                problems.append('execution admission and consensus voting power differ')
            result['observations']['effective_voting_power'] = original[0]['voting_power']
    except Exception:
        problems.append('private native consensus observations are unavailable or differ from the original profile')
    if result['retired'] or context.is_cancelled():
        problems.append('original validator is cancelled or retired')
    result['ready'] = not problems
    result['validator_ready'] = result['ready'] and result['mode'] == 'validator'
    result['problems'] = problems
    return result

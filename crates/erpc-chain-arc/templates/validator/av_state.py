#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original validator owner and per-deployment cancellation, without data deletion."""
import base64
import json
import pathlib
import re

from arc_files import Refused, require, encoded
from av_files import ROOT
import av_accounts
import av_events
import av_storage

OWNER = ROOT + '/owner.json'
OPERATION = ROOT + '/operation.json'
HALT = ROOT + '/startup-revoked.json'
RETIRED = ROOT + '/retired.json'
NETWORKS = json.loads(pathlib.Path(__file__).with_name('networks.json').read_text())['networks']


def contract(value):
    require(isinstance(value, dict) and set(value) == {'owner', 'network', 'chain_id', 'genesis_hash',
                                                    'public_key', 'peer_public_key', 'controller', 'host_binding'},
            'invalid original Arc validator contract')
    require(isinstance(value['owner'], str) and re.fullmatch('[a-z0-9]{26}', value['owner']) and
            isinstance(value['network'], str) and value['network'] in NETWORKS and
            type(value['chain_id']) is int and value['chain_id'] == NETWORKS[value['network']]['chain_id'] and
            value['genesis_hash'] == NETWORKS[value['network']]['genesis_hash'],
            'original Arc validator owner, network or genesis differs')
    require(isinstance(value['controller'], str) and re.fullmatch('0x[0-9a-f]{40}', value['controller']) and
            int(value['controller'][2:], 16) > 0 and isinstance(value['host_binding'], str) and
            re.fullmatch('[0-9a-f]{64}', value['host_binding']), 'invalid original controller or host binding')
    public = base64.b64decode(value['public_key'], validate=True)
    require(len(public) == 32 and any(public) and base64.b64encode(public).decode() == value['public_key'],
            'invalid original public consensus identity')
    peer = base64.b64decode(value['peer_public_key'], validate=True)
    require(len(peer) == 32 and any(peer) and base64.b64encode(peer).decode() == value['peer_public_key'] and
            peer != public, 'local peer identity must be distinct from the external consensus signer')
    return value


def intent(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{32}', value),
            'a fresh 128-bit Arc validator deployment intent is required')
    return value


def original(context, expected):
    contract(expected)
    state = context.json(OWNER, private=True)
    require(state.get('schema') == 'erpc-arc-validator-v1' and state.get('contract') == expected,
            'remote Arc validator original owner/network/controller/key differs')
    return state


def reserve(context, expected):
    contract(expected)
    if context.protected(OWNER, missing=True).exists():
        state = original(context, expected)
        context.save(state)
        context.sync(context.ROOT)
        return state
    pending = context.protected(OWNER + '.pending', missing=True)
    if pending.exists():
        # Atomic original-owner publication may have failed before its rename.
        # Reuse only that exact complete pre-NSS reservation; do not discover new
        # numbers or infer ownership from any existing account or native data.
        state = context.json(OWNER + '.pending', private=True, resync=True)
        require(isinstance(state, dict) and set(state) == {'schema', 'contract', 'accounts', 'storage',
                                                          'phase', 'signer_used', 'generation', 'retired'} and
                state['schema'] == 'erpc-arc-validator-v1' and state['contract'] == expected and
                state['phase'] == 'reserved' and state['signer_used'] is False and
                state['generation'] is None and state['retired'] is False and
                state['accounts']['established'] is False, 'unrecognized original Arc reservation is retained')
        users, groups, engine = av_accounts.verify(state['accounts'], missing=True)
        require(not any(users.values()) and not any(groups.values()) and engine is None,
                'unpublished Arc reservation cannot adopt existing native accounts')
        context.preflight_fresh_namespace(pending_owner=True)
        require(av_storage.fresh(context) == state['storage'],
                'original pending Arc reservation storage changed')
        context.save(state)
        context.sync(context.ROOT)
        return state
    context.preflight_fresh_namespace()
    storage = av_storage.fresh(context)
    accounts = av_accounts.reserve()
    state = {'schema': 'erpc-arc-validator-v1', 'contract': expected, 'accounts': accounts,
             'storage': storage, 'phase': 'reserved', 'signer_used': False,
             'generation': None, 'retired': False}
    context.mkdir(ROOT)
    context.save(state)
    context.sync(context.ROOT)
    return state


def retired(context, state):
    return (context.protected(RETIRED, missing=True).exists() or
            context.protected(RETIRED + '.pending', missing=True).exists() or
            av_events.retired_halt(context) or
            av_events.retirement(context) != state.get('retirement_ack'))


def active_operation(context, state, expected, allow_retired=False):
    intent(expected)
    require(not av_events.pending(context), 'pending lifecycle cancellation requires explicit recovery')
    operation = context.json(OPERATION, private=True, resync=True)
    require(operation.get('history') == av_events.basis(context, durable=True), 'lifecycle history revoked this deployment')
    require(operation.get('owner') == state['contract']['owner'] and operation.get('intent') == expected and
            operation.get('cancelled') is False, 'Arc validator deployment was cancelled or superseded')
    require(context.json(HALT, private=True, resync=True) == {'intent': expected, 'reason': 'new-deployment'},
            'Arc validator operation no longer owns its startup fence')
    require(allow_retired or not retired(context, state), 'Arc validator was retired')
    return operation


def authorize(context, state, expected, target, policy):
    intent(expected)
    context.validate_target(target)
    context.validate_policy(state, policy)
    if context.protected(OPERATION, missing=True).exists():
        previous = context.json(OPERATION, private=True)
        require(previous.get('owner') == state['contract']['owner'], 'foreign lifecycle operation is retained')
        require(previous.get('intent') != expected, 'Arc deployment intent cannot be reused')
    require(not context.protected(av_events.DIRECTORY + '/authorize-' + expected + '.event', missing=True).exists(),
            'previous attempted deployment intent cannot be reused')
    retained_intent = ROOT + '/intents/' + expected + '.json'
    require(not context.protected(retained_intent, missing=True).exists(),
            'previous Arc deployment intent cannot be reused')
    # A new generation cannot leave an older queued activation authoritative if
    # the later operation receipt fails. Publish revocation before that receipt.
    try:
        av_events.append(context, 'authorize', encoded({'owner': state['contract']['owner'], 'intent': expected}), expected)
        av_events.preserve(context)
        context.write(HALT, {'intent': expected, 'reason': 'new-deployment'})
        context.mkdir(ROOT + '/intents')
        context.write(retained_intent, {'owner': state['contract']['owner'], 'intent': expected})
        context.write(OPERATION, {'owner': state['contract']['owner'], 'intent': expected,
                                  'target': target, 'policy': policy, 'cancelled': False, 'history': av_events.basis(context, durable=True)})
    except Exception:
        failures = []
        for action in (context.stop_original, context.disable_original):
            try:
                action(state)
            except Exception:
                failures.append('owned shutdown or disable failed')
        try:
            av_events.preserve(context)
            context.write(HALT, {'intent': None, 'reason': 'failed-deployment'})
        except Exception:
            pass
        raise Refused('Arc deployment publication failed; durable cancellation is not confirmed' +
                      ('; owned shutdown also incomplete' if failures else '; owned shutdown attempted')) from None
    return {'intent': expected, 'authorized': True}


def begin(context, state, expected):
    operation = active_operation(context, state, expected, allow_retired=True)
    fence = context.json(HALT, private=True)
    require(fence == {'intent': expected, 'reason': 'new-deployment'},
            'Arc validator deployment no longer owns its startup fence')
    context.stop_original(state)
    context.assert_all_quiescent(state)
    state['generation'] = expected
    state['phase'] = 'installing'
    state['target'] = operation['target']
    state['policy'] = operation['policy']
    state['retired'] = False
    state['authorization_history'] = operation['history']
    state['retirement_ack'] = av_events.retirement(context)
    state['pending_recovery_ack'] = av_events.pending_history(context)
    context.save(state)
    context.remove(RETIRED)
    return operation


def ready_to_activate(context, state, expected):
    operation = active_operation(context, state, expected)
    require(state.get('generation') == expected and state.get('phase') == 'installed' and
            state.get('target') == operation['target'] and state.get('policy') == operation['policy'],
            'Arc validator generation or installed target differs')
    require(context.json(HALT, private=True, resync=True) == {'intent': expected, 'reason': 'new-deployment'},
            'an explicit stop revoked this Arc validator deployment')
    return operation


def cancel_and_stop(context, state, retire=False):
    # The caller proves the immutable contract before entering this function.
    # Persistence, process shutdown and unit disable are independent attempts:
    # storage failure cannot suppress the original process shutdown attempt.
    failures = []
    try:
        retire = retire or retired(context, state)
    except Exception:
        retire = True
        failures.append('original cancellation reason could not be established')
    try:
        av_events.append(context, 'retire' if retire else 'stop', encoded({'owner': state['contract']['owner']}))
    except Exception:
        failures.append('durable lifecycle evidence was not confirmed')
    def persist():
        # Never truncate prior restrictive pending/committed evidence unless its
        # original bytes have first been retained behind durable directory barriers.
        av_events.preserve(context)
        errors = []
        if retire:
            try:
                context.write(RETIRED, {'owner': state['contract']['owner']})
            except Exception:
                errors.append('retirement')
        try:
            context.write(HALT, {'intent': None, 'reason': 'retired' if retire else 'stopped'})
        except Exception:
            errors.append('startup revocation')
        try:
            if context.protected(OPERATION, missing=True).exists():
                operation = context.json(OPERATION, private=True)
                require(operation.get('owner') == state['contract']['owner'], 'foreign operation cannot be cancelled')
                operation['cancelled'] = True
                context.write(OPERATION, operation)
        except Exception:
            errors.append('operation revocation')
        require(not errors, 'Arc cancellation receipts were not all durable')
    persistence_failed = False
    try:
        persist()
    except Exception:
        persistence_failed = True
        failures.append('durable cancellation was not confirmed')
    for action in (context.stop_original, context.disable_original):
        try:
            action(state)
        except Exception:
            failures.append('original shutdown or disable was incomplete')
    if persistence_failed:
        try:
            persist()
        except Exception:
            pass
    require(not failures, 'Arc cancellation incomplete: ' + '; '.join(failures) +
            '; original data, ciphertext, signing history and ingress retained')
    return {'stopped': True, 'retired': retire, 'data_retained': True}

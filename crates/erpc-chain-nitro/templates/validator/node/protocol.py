# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Closed public controller protocol shared with the Rust inventory/frontend."""
import re
import scope
from state import contract, token
from storage import require

VERSION = scope.VERSION
COMMIT = scope.COMMIT
IMAGE = scope.IMAGE
IMAGE_ID = scope.IMAGE_ID
TARGET_FIELDS = {'phase', 'version', 'commit', 'image', 'image_id', 'helpers_sha256', 'config_id'}


def target(value, helpers_sha256=None):
    require(isinstance(value, dict) and set(value) == TARGET_FIELDS, 'invalid exact validator deployment target')
    require(value['phase'] in ('observing', 'active') and value['version'] == VERSION
            and value['commit'] == COMMIT and value['image'] == IMAGE and value['image_id'] == IMAGE_ID,
            'validator target is outside the reviewed native catalog')
    for key in ('helpers_sha256', 'config_id'):
        require(isinstance(value[key], str) and re.fullmatch('[0-9a-f]{64}', value[key]), 'invalid validator content identity')
    require(helpers_sha256 is None or value['helpers_sha256'] == helpers_sha256,
            'validator target does not identify this exact carried helper profile')
    return value


def transition(previous, wanted, activated=False):
    """Reject an old CLI against a newer/unknown installed catalog before drain."""
    target(wanted)
    if previous is not None:
        target(previous)
    require(not activated or wanted['phase'] == 'active',
            'an activated signer cannot discard its original signing history or become a fresh observer')
    return wanted


def request(value):
    require(isinstance(value, dict) and isinstance(value.get('action'), str), 'invalid validator control request')
    action = value['action']
    fields = {'action', 'contract'}
    if action == 'preflight':
        require(set(value) in ({'action'}, fields), 'invalid validator preflight request')
        if 'contract' in value: contract(value['contract'])
        return value
    if action in ('init', 'metadata', 'status', 'start', 'restart', 'stop', 'destroy', 'identity',
                  'registration-prepare', 'registration-validate', 'registration-status'):
        pass
    elif action == 'upgrade-volume-authority': fields |= {'original_root'}
    elif action == 'prepare': fields |= {'intent', 'target'}
    elif action in ('import-upstreams','provider-stage-import'): fields |= {'intent', 'secret'}
    elif action == 'provider-stage-authorize': fields |= {'intent'}
    elif action == 'import-wallet': fields |= {'intent', 'secret', 'restore'}
    elif action == 'wallet-stage-authorize': fields |= {'intent','restore'}
    elif action == 'wallet-stage-import': fields |= {'intent','restore','secret'}
    elif action == 'firewall-confirm': fields |= {'intent', 'operation', 'bundle'}
    else: raise ValueError('unknown validator control operation')
    require(set(value) == fields, 'unexpected validator control fields')
    contract(value['contract'])
    if 'intent' in value: token(value['intent'])
    if action == 'prepare': target(value['target'])
    if action == 'firewall-confirm':
        require(isinstance(value['operation'], str) and re.fullmatch('r-[a-z0-9-]+', value['operation'])
                and len(value['operation']) <= 80 and isinstance(value['bundle'], str)
                and re.fullmatch('[a-f0-9]{64}', value['bundle']), 'invalid immutable firewall receipt')
    if action == 'upgrade-volume-authority' and value['original_root'] is not None:
        import volumes
        require(isinstance(value['original_root'],dict),'invalid original ROOT evidence')
        volumes.historical_root(value['original_root'],value['original_root'].get('inode'))
    if action in ('import-wallet','wallet-stage-authorize','wallet-stage-import'): require(type(value['restore']) is bool, 'invalid wallet restoration request')
    if 'secret' in value:
        require(isinstance(value['secret'], str) and 0 < len(value['secret']) <= 131072, 'invalid concealed validator input')
    return value

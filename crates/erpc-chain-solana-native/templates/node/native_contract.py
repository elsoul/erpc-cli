# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Exact public ownership shape shared with the native controller inventory."""
from pathlib import Path
import re
from native_files import require

MOUNTS = {kind: Path('/mnt/erpc-solana-' + kind) for kind in ('accounts', 'ledger', 'snapshots')}
KEYS = ('identity_account', 'vote_account', 'authority_account')


def public_key(value):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    require(isinstance(value, str) and 32 <= len(value) <= 44, 'invalid public account')
    number = 0
    for char in value:
        require(char in alphabet, 'invalid public account encoding')
        number = number * 58 + alphabet.index(char)
    leading = len(value) - len(value.lstrip('1'))
    require(0 < number < 2**256 and leading + (number.bit_length() + 7) // 8 == 32,
            'noncanonical public account')
    return value


def validate(contract):
    require(isinstance(contract, dict) and set(contract) == {
        'schema', 'profile', 'inventory_id', 'name', 'network', 'host_binding', *KEYS, 'volumes'},
        'native ownership fields differ')
    require(type(contract['schema']) is int and contract['schema'] == 1
            and contract['profile'] in ('agave-native', 'agave-native-rpc'), 'unsupported native ownership format')
    require(isinstance(contract['inventory_id'], str) and re.fullmatch('[a-z0-9]{26}', contract['inventory_id'])
            and isinstance(contract['name'], str) and re.fullmatch('[a-z][a-z0-9-]{0,31}', contract['name'])
            and contract['network'] in ('mainnet', 'testnet')
            and isinstance(contract['host_binding'], str) and re.fullmatch('[a-f0-9]{64}', contract['host_binding']),
            'invalid native host ownership')
    if contract['profile'] == 'agave-native-rpc':
        public_key(contract['identity_account'])
        require(contract['vote_account'] is None and contract['authority_account'] is None,
                'native RPC cannot contain financial accounts')
    else:
        keys = [public_key(contract[name]) for name in KEYS]
        require(len(set(keys)) == len(KEYS), 'native public accounts must be distinct')
    validate_volumes(contract['volumes'])
    return contract


def validate_volumes(volumes):
    require(isinstance(volumes, dict) and set(volumes) == set(MOUNTS), 'native volume fields differ')
    for value in volumes.values():
        require(isinstance(value, str) and re.fullmatch('[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', value)
                and any(char not in '0-' for char in value), 'invalid native filesystem UUID')
    require(len(set(volumes.values())) == len(MOUNTS), 'native filesystems must be distinct')
    return volumes

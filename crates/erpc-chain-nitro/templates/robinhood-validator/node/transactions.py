# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Limit Robinhood Defensive sends to the original admitted wallet and rollup.

This module never creates a signature. Funding, WETH wrapping, ERC20 approval,
owner changes, arbitrary transfers and arbitrary contract execution are not
native participation methods. The caller holds the current send-authority lock
and supplies a fresh verified protocol observation before forwarding bytes.
"""
import re
import scope
import abi
import admission
import crypto
import rlp
from storage import require

# Explicit ERPC maximums, not promises about fee markets or challenge costs.
MAX_FEE_WEI = 100 * 10**9
MAX_GAS = 30_000_000


def payload(recipient, data, wallet, observation):
    family, name, values = abi.decode(data)
    require(family=='rollup' and name in ('newStakeOnNewAssertion','stakeOnNewAssertion')
            and recipient==admission.ROLLUP, 'Defensive cannot send confirmations, challenge edges or unrelated methods')
    require(observation.get('wallet')==wallet and observation.get('rollup')==admission.ROLLUP
            and observation.get('stake_token')==admission.WETH and observation.get('admitted') is True
            and observation.get('network')==scope.NETWORK and observation.get('strategy')=='Defensive'
            and observation.get('parent_chain_id')==scope.PARENT_ID and observation.get('child_chain_id')==scope.CHILD_ID,
            'native Defensive protocol observation differs')
    require(observation.get('funding_checks_passed') is True and int(observation.get('eth_balance_wei','0'))>0,
            'original external funding and allowance reserve is insufficient')
    require(observation.get('rollup_paused') is False, 'qualified rollup is paused or pause state is unavailable')
    challenge=admission.address(observation.get('challenge_manager'))
    require(0<int(observation['assertion_bond_wei'])<=scope.ASSERTION_BOND_LIMIT_WEI,
            'live assertion bond exceeds the source-qualified Defensive limit')
    if name in ('newStakeOnNewAssertion', 'stakeOnNewAssertion'):
        inputs = values[1] if name == 'newStakeOnNewAssertion' else values[0]
        config = inputs[0][2]
        require(config[2] == challenge and 0 < config[1] <= int(observation['assertion_bond_wei']),
                'assertion bond or challenge manager exceeds the qualified observation')
        require(inputs[1][1] <= 3 and inputs[2][1] <= 3, 'invalid native assertion machine status')
        if name == 'newStakeOnNewAssertion':
            require(observation.get('is_staked') is False,'original wallet is already staked')
            require(values[0] == config[1] and values[3] == wallet,
                    'new assertion changes the original withdrawal address or stakes extra tokens')
            require(values[0] <= int(observation['weth_balance_wei'])
                    and values[0] <= int(observation['rollup_allowance_wei']),
                    'external allocated WETH cannot fund this assertion')
        else:
            require(observation.get('is_staked') is True and int(observation['existing_stake_wei'])>=config[1],
                    'original existing stake does not cover this defensive assertion')
    return name


def signed(encoded, wallet, observation, recover=crypto.sender):
    admission.address(wallet)
    require(isinstance(encoded, str) and re.fullmatch('0x(?:[0-9a-fA-F]{2}){1,1048576}', encoded),
            'invalid bounded signed transaction')
    transaction = rlp.dynamic_fee(bytes.fromhex(encoded[2:]))
    require(transaction['chain'] == scope.PARENT_ID and transaction['nonce'] < 2**64 and transaction['value'] == 0
            and transaction['access_list'] == [] and 0 < transaction['gas'] <= MAX_GAS
            and transaction['tip'] <= transaction['fee'] <= MAX_FEE_WEI,
            'native transaction exceeds the Ethereum, value, access-list or fee policy')
    require(transaction['gas']*transaction['fee']<=int(observation['eth_balance_wei']),
            'maximum transaction gas charge exceeds observed dedicated ETH funding')
    name = payload(transaction['recipient'], transaction['data'], wallet, observation)
    digest = crypto.keccak(transaction['signing_payload'])
    require(recover(digest, transaction['parity'], transaction['r'], transaction['s']) == wallet,
            'signed transaction does not belong to the original dedicated wallet')
    return name


def estimate(value, wallet, observation):
    require(isinstance(value, dict) and set(value) <= {'from', 'to', 'data', 'input', 'value', 'gas',
                'gasPrice', 'maxFeePerGas', 'maxPriorityFeePerGas', 'accessList'}
            and value.get('from', '').lower() == wallet and value.get('to', '').lower()==admission.ROLLUP, 'gas estimate is outside the original native wallet')
    require(('data' in value) != ('input' in value) and value.get('accessList', []) == [],
            'ambiguous native transaction estimate')
    require(admission.quantity(value.get('value', '0x0')) == 0, 'native gas estimate transfers ETH')
    for name in ('gasPrice', 'maxFeePerGas', 'maxPriorityFeePerGas'):
        if name in value: require(admission.quantity(value[name]) <= MAX_FEE_WEI, 'native gas estimate exceeds fee policy')
    if 'gas' in value: require(0 < admission.quantity(value['gas']) <= MAX_GAS, 'native gas estimate exceeds gas policy')
    encoded = value.get('data', value.get('input'))
    require(isinstance(encoded, str) and re.fullmatch('0x(?:[0-9a-fA-F]{2}){4,1048576}', encoded),
            'invalid native estimate calldata')
    return payload(value['to'].lower(), bytes.fromhex(encoded[2:]), wallet, observation)

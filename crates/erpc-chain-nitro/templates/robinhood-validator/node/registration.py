# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Unsigned external funding and rollup-only allowance for admitted Defensive.

Defensive does not initiate challenge edges or confirmations, so this profile
neither requests a challenge-manager allowance nor exposes those native sends.
Administrator admission, funding, wrapping, approvals and withdrawals are external.
"""
import admission
import scope
from storage import require


def number(value):
    require(isinstance(value,str) and value.isdecimal() and 0<=int(value)<2**256,
            'invalid observed external amount')
    return int(value)


def word(value):
    require(type(value) is int and 0<=value<2**256,'invalid external ABI amount')
    return format(value,'064x')


def prepare(observed):
    wallet=admission.address(observed['wallet'])
    require(observed.get('network')==scope.NETWORK and observed.get('strategy')=='Defensive'
            and observed.get('parent_chain_id')==scope.PARENT_ID and observed.get('child_chain_id')==scope.CHILD_ID
            and observed.get('rollup')==admission.ROLLUP and observed.get('stake_token')==admission.WETH
            and observed.get('challenge_sends_enabled') is False,
            'external funding context differs from the sealed Defensive profile')
    required=number(observed['external_weth_budget_wei'])
    expected=0 if observed['is_staked'] else number(observed['assertion_bond_wei'])
    require(required==expected and required<=scope.ASSERTION_BOND_LIMIT_WEI,
            'external assertion budget exceeds the qualified profile')
    balance=number(observed['weth_balance_wei']);allowance=number(observed['rollup_allowance_wei'])
    shortfall=max(0,required-balance);needed=allowance<required;chain=hex(scope.PARENT_ID)
    def approval(amount):
        return {'chainId':chain,'from':wallet,'to':admission.WETH,'value':'0x0',
                'data':'0x095ea7b3'+admission.ROLLUP[2:].rjust(64,'0')+word(amount)}
    return {'financial_action_performed':False,'signing_required_externally':True,
            'network':scope.NETWORK,'strategy':'Defensive','original_wallet':wallet,
            'snapshot_block':observed['block'],'snapshot_hash':observed['block_hash'],
            'admitted':observed['admitted'],'administrator_admission_required':not observed['admitted'],
            'administrator_authority_verified':False,'deployed_implementation_verified':False,
            'gas_balance_wei':observed['eth_balance_wei'],'gas_adequacy_verified':False,
            'weth_shortfall_wei':str(shortfall),'assertion_bond_limit_wei':str(scope.ASSERTION_BOND_LIMIT_WEI),
            'total_lifetime_budget_cap':False,'challenge_sends_enabled':False,
            'approvals':[{'spender':admission.ROLLUP,'required_allowance_wei':str(required),
                'current_allowance_wei':str(allowance),'needed':needed,
                'reset_allowance_first':approval(0) if needed and allowance else None,
                'unsigned_transaction':approval(required) if needed else None}],
            'optional_external_wrap':{'needed':shortfall>0,'unsigned_transaction':{
                'chainId':chain,'from':wallet,'to':admission.WETH,'value':hex(shortfall),'data':'0xd0e30db0'}},
            'alternative_external_weth_transfer':{'needed':shortfall>0,'cold_sender_selected_externally':True,
                'unsigned_transaction':{'chainId':chain,'to':admission.WETH,'value':'0x0',
                    'data':'0xa9059cbb'+wallet[2:].rjust(64,'0')+word(shortfall)}},
            'notice':'Admission is an external administrator action. Fund only the dedicated participation wallet, wrap and approve externally, and revalidate. One assertion bond is not a total gas or loss budget. Native Defensive excludes MakeNodes, confirmations, challenge-edge creation and withdrawals.'}

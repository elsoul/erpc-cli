# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Unsigned external funding/allowance instructions from one finalized snapshot.

ERC20 approve/transfer (EIP20) and canonical WETH9 deposit are external operator
steps. This module only formats public calldata; it has no key or send API.
"""
import admission
from storage import require


def number(value):
    require(isinstance(value,str) and value.isdecimal() and 0 <= int(value) < 2**256,
            'invalid observed external funding amount')
    return int(value)


def word(value):
    require(type(value) is int and 0 <= value < 2**256,'invalid external ABI amount')
    return format(value,'064x')


def prepare(observed):
    wallet=admission.address(observed['wallet'])
    require(observed['rollup']==admission.ROLLUP and observed['challenge_manager']==admission.CHALLENGE
            and observed['stake_token']==admission.WETH,'unqualified external registration context')
    required=number(observed['external_weth_budget_wei']); balance=number(observed['weth_balance_wei'])
    assertion=0 if observed['is_staked'] else number(observed['assertion_bond_wei'])
    challenge=sum(number(value) for value in observed['challenge_path_bonds_wei'])
    require(assertion+challenge==required,'external funding budget differs from observed bonds')
    shortfall=max(0,required-balance)
    approvals=[]
    for spender,amount,key in [(admission.ROLLUP,assertion,'rollup_allowance_wei'),
                               (admission.CHALLENGE,challenge,'challenge_allowance_wei')]:
        needed=number(observed[key])<amount
        reset={'chainId':'0x1','from':wallet,'to':admission.WETH,'value':'0x0',
               'data':'0x095ea7b3'+spender[2:].rjust(64,'0')+word(0)} if needed and number(observed[key])>0 else None
        approvals.append({'spender':spender,'required_allowance_wei':str(amount),
                          'current_allowance_wei':observed[key],'needed':needed, 'reset_allowance_first':reset,
                          'unsigned_transaction':{'chainId':'0x1','from':wallet,'to':admission.WETH,'value':'0x0',
                                                  'data':'0x095ea7b3'+spender[2:].rjust(64,'0')+word(amount)} if needed else None})
    return {'financial_action_performed':False,'signing_required_externally':True,
            'snapshot_block':observed['block'],'snapshot_hash':observed['block_hash'],
            'original_wallet':wallet,'gas_balance_wei':observed['eth_balance_wei'],'gas_adequacy_verified':False,
            'weth_shortfall_wei':str(shortfall),'approvals':approvals,
            'optional_external_wrap':{'needed':shortfall>0,'unsigned_transaction':{
                'chainId':'0x1','from':wallet,'to':admission.WETH,'value':hex(shortfall),'data':'0xd0e30db0'}},
            'alternative_external_weth_transfer':{'needed':shortfall>0,'cold_sender_selected_externally':True,
                'unsigned_transaction':{'chainId':'0x1','to':admission.WETH,'value':'0x0',
                    'data':'0xa9059cbb'+wallet[2:].rjust(64,'0')+word(shortfall)}},
            'notice':'Use an external signing tool for funding, wrapping and exact WETH allowances. Revalidate current amounts before activating. Never fund this wallet with owner assets beyond the dedicated participation budget.'}

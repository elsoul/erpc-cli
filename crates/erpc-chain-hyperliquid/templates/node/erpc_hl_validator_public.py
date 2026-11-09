# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fixed read-only registration/funding observations, never native action submission."""
from decimal import Decimal
import re
import time
from erpc_hl_common import require
from erpc_hl_public import post


def money(value):
    require(isinstance(value,str) and re.fullmatch(r'(0|[1-9][0-9]{0,18})(\.[0-9]{1,18})?',value),
            'bounded nonnegative decimal observation required')
    return Decimal(value)


def fresh(value,now):
    require(type(value) is int and value>0 and now-120000<=value<=now+30000,
            'official native observation is missing or outside clock tolerance')


def registration(profile,identity,now=None):
    observed=int(time.time()*1000) if now is None else now
    before=post(profile['info_url'],{'type':'exchangeStatus'})
    fresh(before.get('time'),observed)
    entries=post(profile['info_url'],{'type':'validatorSummaries'})
    require(isinstance(entries,list) and len(entries)<=10000,'invalid bounded validator observation')
    selected=[]
    for entry in entries:
        require(isinstance(entry,dict) and isinstance(entry.get('validator'),str)
                and re.fullmatch('0x[a-f0-9]{40}',entry['validator'])
                and isinstance(entry.get('signer'),str) and re.fullmatch('0x[a-f0-9]{40}',entry['signer']),
                'validator observation contains invalid identity fields')
        if entry['validator']==identity['validator']:selected.append(entry)
        if entry['signer']==identity['signer']:
            require(entry['validator']==identity['validator'],'consensus signer is registered to another validator')
    require(len(selected)<=1,'ambiguous original validator observation')
    after=post(profile['info_url'],{'type':'exchangeStatus'})
    fresh(after.get('time'),int(time.time()*1000) if now is None else now)
    require(after['time']>=before['time'],'official native observation moved backwards')
    result={'registered':bool(selected),'validator':identity['validator'],'signer':identity['signer'],
            'observed_core_time':after['time'],'node_ip_proof':'not available in validatorSummaries',
            'signing_by_erpc':False,'submission_by_erpc':False}
    if not selected:
        return dict(result,state='not_registered',active=False,jailed=None)
    entry=selected[0]
    require(entry['signer']==identity['signer'] and type(entry.get('isActive')) is bool
            and type(entry.get('isJailed')) is bool and type(entry.get('stake')) is int and entry['stake']>=0
            and (entry.get('unjailableAfter') is None or type(entry['unjailableAfter']) is int),
            'original validator signer or state is unavailable or changed')
    # An active-set member may simultaneously be jailed. Do not report it as
    # currently participating merely because the rank flag is true.
    state='registered_jailed' if entry['isJailed'] else ('active' if entry['isActive'] else 'registered_inactive')
    return dict(result,state=state,active=entry['isActive'] and not entry['isJailed'],
                jailed=entry['isJailed'],stake_wei=entry['stake'],unjailable_after=entry.get('unjailableAfter'))


def funding(profile,identity,limit,now=None):
    ceiling=money(limit)
    require(ceiling>0,'an explicit positive dedicated hot-balance ceiling is required')
    observed=int(time.time()*1000) if now is None else now
    balances={}
    for role in ('validator','signer'):
        state=post(profile['info_url'],{'type':'clearinghouseState','user':identity[role]})
        require(isinstance(state,dict) and isinstance(state.get('marginSummary'),dict),
                'native perps balance observation is unavailable')
        fresh(state.get('time'),observed)
        balance=money(state['marginSummary'].get('totalRawUsd'))
        require(balance>0,'both external validator and consensus signer require nonzero perps USDC')
        if role=='signer':
            require(balance<=ceiling and state.get('assetPositions')==[],
                    'hot wallet exceeds its explicit funding ceiling or carries trading positions')
        balances[role]=str(balance)
    orders=post(profile['info_url'],{'type':'openOrders','user':identity['signer']})
    require(orders==[],'dedicated consensus signer has open trading orders')
    return {'validator_perps_usdc':balances['validator'],'signer_perps_usdc':balances['signer'],
            'hot_balance_ceiling_usdc':limit,'observed_at':observed,'funding_by_erpc':False}

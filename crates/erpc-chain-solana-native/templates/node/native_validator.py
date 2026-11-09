# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fresh public registration checks for the original native identity-only voter.

This module never signs or broadcasts. Native Tower/vote-history restoration
remains the qualified client's responsibility, before networking is started.
"""
import time
import urllib.request
from native_contract import public_key
from native_files import encoded, json_value, require
from native_runtime_observer import NoRedirect

PUBLIC = {'mainnet':'https://api.mainnet-beta.solana.com', 'testnet':'https://api.testnet.solana.com'}
VOTE_PROGRAM = 'Vote111111111111111111111111111111111111111'
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def uint(value):
    require(type(value) is int and 0 <= value < 2**64, 'invalid public unsigned integer')
    return value


def bls_key(value):
    require(isinstance(value,str) and 1 <= len(value) <= 66 and all(c in ALPHABET for c in value),
            'invalid compressed BLS public encoding')
    number=0
    for character in value:number=number*58+ALPHABET.index(character)
    leading=len(value)-len(value.lstrip('1'))
    require(number>0 and leading+(number.bit_length()+7)//8==48,'BLS public key must encode exactly 48 bytes')
    return value


def registration(value):
    require(isinstance(value,dict) and set(value)=={'network','identity','vote_account','withdrawer','bls','commission'}
            and value['network'] in PUBLIC and type(value['commission']) is int and 0<=value['commission']<=100,
            'complete original public validator registration required')
    for field in ('identity','vote_account','withdrawer'):public_key(value[field])
    require(len({value[field] for field in ('identity','vote_account','withdrawer')})==3,
            'online identity, vote account and external withdrawal authority must differ')
    bls_key(value['bls'])
    return value


def public_rpc(network,method,params):
    require(network in PUBLIC and method in ('getGenesisHash','getEpochInfo','getBlockTime','getAccountInfo',
                                            'getMinimumBalanceForRentExemption','getBalance','getVoteAccounts'),
            'unsupported read-only validator observation')
    request=urllib.request.Request(PUBLIC[network],data=encoded({'jsonrpc':'2.0','id':1,'method':method,'params':params}),
                                  headers={'Content-Type':'application/json','Accept-Encoding':'identity'})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    with opener.open(request,timeout=8) as response:
        require(response.status==200 and response.headers.get('Content-Encoding','identity')=='identity',
                'public validator response status or encoding differs')
        raw=response.read(262145)
    require(len(raw)<=262144,'public validator response exceeds its bound')
    value=json_value(raw)
    require(isinstance(value,dict) and value.get('jsonrpc')=='2.0' and type(value.get('id')) is int and value['id']==1
            and 'error' not in value and 'result' in value,'public validator RPC response is unavailable')
    return value['result']


def vote_account(value,expected,epoch):
    registration(expected);uint(epoch)
    require(isinstance(value,dict) and value.get('owner')==VOTE_PROGRAM and value.get('executable') is False,
            'reserved address is not an owned vote-program account')
    data=value.get('data',{});parsed=data.get('parsed',{})
    require(data.get('program')=='vote' and parsed.get('type')=='vote','native parsed vote account required')
    info=parsed.get('info',{})
    require(info.get('nodePubkey')==expected['identity'] and info.get('authorizedWithdrawer')==expected['withdrawer']
            and info.get('blsPubkeyCompressed')==expected['bls'],'vote account differs from original public authorities')
    require(uint(info.get('commission'))==expected['commission']
            and uint(info.get('inflationRewardsCommissionBps'))==expected['commission']*100,
            'native commission differs or contains a fractional percentage')
    voters=info.get('authorizedVoters')
    require(isinstance(voters,list) and 1<=len(voters)<=64,'bounded native voter schedule required')
    schedule={}
    for row in voters:
        require(isinstance(row,dict),'invalid native voter entry')
        when=uint(row.get('epoch'));who=public_key(row.get('authorizedVoter'))
        require(when not in schedule,'duplicate voter epoch')
        schedule[when]=who
    effective=[when for when in schedule if when<=epoch]
    require(effective and schedule[max(effective)]==expected['identity']
            and all(who==expected['identity'] for when,who in schedule.items() if when>epoch),
            'current or scheduled future voting authority differs')
    return {'balance_lamports':uint(value.get('lamports')),'space':uint(value.get('space')),
            'current_voter':schedule[max(effective)],'future_voters':{str(k):v for k,v in schedule.items() if k>epoch}}


def epoch_position(value):
    require(isinstance(value,dict),'public epoch observation unavailable')
    epoch,slot,index,size=(uint(value.get(key)) for key in ('epoch','absoluteSlot','slotIndex','slotsInEpoch'))
    require(size>0 and index<size and index<=slot,'invalid epoch position')
    return epoch,slot


def fresh(timestamp,now):
    uint(timestamp)
    require(-30<=int(now)-timestamp<=120,'public validator block time is stale or in the future')
    return timestamp


def observe(expected,genesis,call=public_rpc,now=time.time):
    registration(expected);public_key(genesis)
    started=int(now());network=expected['network']
    require(call(network,'getGenesisHash',[])==genesis,'validator observation genesis differs')
    epoch,first=epoch_position(call(network,'getEpochInfo',[{'commitment':'finalized'}]))
    fresh(call(network,'getBlockTime',[first]),now())
    account=call(network,'getAccountInfo',[expected['vote_account'],{'encoding':'jsonParsed','commitment':'finalized','minContextSlot':first}])
    slot=uint(account.get('context',{}).get('slot'))
    require(slot>=first,'vote-account context moved backwards')
    vote=vote_account(account.get('value'),expected,epoch)
    require(1<=vote['space']<=16384,'vote-account size is unavailable')
    rent=uint(call(network,'getMinimumBalanceForRentExemption',[vote['space'],{'commitment':'finalized'}]))
    require(rent>0 and vote['balance_lamports']>=rent,'vote account does not cover the current rent quote')
    identity=call(network,'getBalance',[expected['identity'],{'commitment':'finalized','minContextSlot':slot}])
    identity_slot=uint(identity.get('context',{}).get('slot'));balance=uint(identity.get('value'))
    require(identity_slot>=slot and balance>0,'original node identity is unfunded or its observation is stale')
    final_epoch,final_slot=epoch_position(call(network,'getEpochInfo',[{'commitment':'finalized','minContextSlot':identity_slot}]))
    require(final_epoch==epoch and final_slot>=identity_slot and final_slot-first<=300,'validator observation crossed its epoch or slot window')
    timestamp=fresh(call(network,'getBlockTime',[final_slot]),now())
    require(0<=int(now())-started<=60,'validator observation exceeded its time window')
    return {'registration_verified':True,'epoch':epoch,'slot':slot,'finalized_slot':final_slot,'block_time':timestamp,
            'identity_lamports':str(balance),'vote_lamports':str(vote['balance_lamports']),'rent_lamports':str(rent),
            'current_voter':vote['current_voter'],'future_voters':vote['future_voters'],
            'consensus_admission':'native protocol and stake rules apply; public account binding is not a vote or reward guarantee'}


def participation(expected, genesis, call=public_rpc, now=time.time):
    """Require an observed current staked vote account, not merely registration.

    The128-slot recency bound is an ERPC readiness policy. This observation
    cannot prove reward eligibility or exclusive possession of a copied key.
    """
    started = int(now())
    registration_state = observe(expected, genesis, call, now)
    value = call(expected['network'], 'getVoteAccounts', [{'commitment':'finalized',
        'votePubkey':expected['vote_account'], 'keepUnstakedDelinquents':True, 'delinquentSlotDistance':128}])
    require(isinstance(value,dict) and set(value)=={'current','delinquent'}
            and all(isinstance(value[key],list) for key in value)
            and len(value['current'])+len(value['delinquent'])<=1,'ambiguous original vote-account participation')
    epoch, slot = epoch_position(call(expected['network'],'getEpochInfo',[{'commitment':'finalized'}]))
    require(epoch==registration_state['epoch'] and 0<=slot-registration_state['finalized_slot']<=300,
            'vote participation observation crossed its epoch or slot window')
    fresh(call(expected['network'],'getBlockTime',[slot]),now())
    require(0<=int(now())-started<=60,'vote participation observation exceeded its time window')
    result = dict(registration_state, validator_ready=False, participation_observed=False, activated_stake_lamports='0')
    rows = value['current']+value['delinquent']
    if not rows:return result
    row=rows[0]
    require(isinstance(row,dict) and row.get('votePubkey')==expected['vote_account']
            and row.get('nodePubkey')==expected['identity']
            and uint(row.get('commission'))==expected['commission']
            and type(row.get('epochVoteAccount')) is bool, 'vote participation belongs to another original authority')
    stake=uint(row.get('activatedStake'));last=uint(row.get('lastVote'))
    require(last<=slot,'vote participation is ahead of the finalized observation')
    ready=bool(value['current']) and row['epochVoteAccount'] and stake>0 and last>0 and slot-last<=128
    result.update(validator_ready=ready,participation_observed=True,activated_stake_lamports=str(stake),
                  last_vote=last,vote_age_slots=slot-last,current=bool(value['current']),epoch_vote_account=row['epochVoteAccount'])
    return result

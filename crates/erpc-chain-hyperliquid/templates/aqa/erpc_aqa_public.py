# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fresh public agent association, never approval signing or vote submission."""
import re
import time
import urllib.request
from erpc_aqa_common import Refused,json_bytes,require,unique_json

URLS={'mainnet':'https://api.hyperliquid.xyz/info','testnet':'https://api.hyperliquid-testnet.xyz/info'}


class Revoked(Refused):
    """Observed removal/replacement/expiry must never authorize key reuse."""


def approval_require(value,message):
    if not value:raise Revoked(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ValueError('public AQA observation redirected')


def post(network,request):
    require(network in URLS and request.get('type') in
            ('exchangeStatus','extraAgents','userRole','validatorSummaries'),'unsupported public observation')
    value=urllib.request.Request(URLS[network],data=json_bytes(request),headers={'Content-Type':'application/json'})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect)
    with opener.open(value,timeout=20) as response:
        require(response.status==200 and response.geturl()==URLS[network],'public observation origin differs')
        raw=response.read(1048577)
    require(0<len(raw)<=1048576,'public observation exceeds its bound')
    return unique_json(raw)


def address(value):
    require(isinstance(value,str) and re.fullmatch('0x[a-f0-9]{40}',value)
            and value!='0x'+'0'*40,'invalid public address observation')
    return value


def timestamp(value,now):
    require(type(value)is int and now-120000<=value<=now+30000,'public network clock is stale or unavailable')


def observe(contract,now=None):
    clock=int(time.time()*1000) if now is None else now
    network=contract['network'];identity=contract['identity']
    before=post(network,{'type':'exchangeStatus'});timestamp(before.get('time'),clock)
    rows=post(network,{'type':'extraAgents','user':identity['agent_master']})
    require(isinstance(rows,list) and len(rows)<=1000,'invalid public agent list')
    selected=[]
    for row in rows:
        require(isinstance(row,dict) and isinstance(row.get('name'),str) and len(row['name'])<=256,
                'invalid named agent observation')
        address(row.get('address'))
        expires=row.get('validUntil')
        # The public API also returns null (independently observed); null is
        # not a claim that approval is permanent. Recheck the relationship live.
        require('validUntil' in row and (expires is None or type(expires)is int and 0<expires<2**63),
                'invalid agent expiration observation')
        if row['name']==identity['agent_name'] or row['address']==identity['agent']:
            approval_require(row['name']==identity['agent_name'] and row['address']==identity['agent'],
                    'original named agent was replaced or reapproved under another name')
            selected.append(row)
    require(len(selected)<=1,'original named agent approval is ambiguous')
    approval_require(len(selected)==1,'original named agent approval is absent')
    expires=selected[0]['validUntil']
    approval_require(expires is None or expires>clock,'original agent approval is expired')
    require(expires is None or expires>clock+120000,'original agent approval is too near expiration')
    role=post(network,{'type':'userRole','user':identity['agent']})
    require(isinstance(role,dict) and role.get('role') in ('agent','user','missing','vault','subAccount'),
            'public agent role observation is malformed')
    approval_require(role.get('role')=='agent','original address is no longer an approved agent')
    require(isinstance(role.get('data'),dict),'public agent relationship is malformed')
    address(role['data'].get('user'))
    approval_require(role['data']['user']==identity['agent_master'],'agent master relationship differs')
    validators=post(network,{'type':'validatorSummaries'})
    require(isinstance(validators,list) and len(validators)<=10000,'invalid public validator list')
    matches=[]
    for row in validators:
        require(isinstance(row,dict),'invalid public validator entry')
        address(row.get('validator'));address(row.get('signer'))
        if row['validator']==identity['validator']:matches.append(row)
    require(len(matches)==1 and matches[0]['signer']==identity['consensus_signer']
            and type(matches[0].get('isActive'))is bool and type(matches[0].get('isJailed'))is bool,
            'original validator consensus relationship is absent or changed')
    after=post(network,{'type':'exchangeStatus'})
    timestamp(after.get('time'),int(time.time()*1000) if now is None else now)
    require(after['time']>=before['time'],'public observation moved backwards')
    return {'approval':{'master':identity['agent_master'],'agent':identity['agent'],
                        'name':identity['agent_name'],'valid_until':expires},
            'validator_active':matches[0]['isActive'] and not matches[0]['isJailed'],
            'observed_core_time':after['time'],'vote_eligibility':'not established by agent approval',
            'accepted_vote':None,'submitted_by_erpc_observer':False}

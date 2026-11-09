# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fixed-purpose authenticated local validator observations; no redirects/proxies."""
import base64
import hmac
import json
import re
import ssl
import time
import urllib.error
import urllib.request
from eth_files import encoded,require,unique,run
import eth_validator_custody as custody
import eth_validator_engine as engine
import eth_validator_tls as tls

CHAIN_IDS={'mainnet':1,'hoodi':560048}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*_args,**_kwargs):return None


def fetch(state,expected,purpose,path,payload=None):
    require(purpose in ('engine','beacon'),'unknown original observation purpose')
    if purpose=='engine':require(path=='/','fixed engine observation path required')
    else:require(path in ('/eth/v1/beacon/genesis','/eth/v1/node/syncing')
                 or re.fullmatch('/eth/v1/beacon/states/head/validators/0x[a-f0-9]{96}',path),'fixed beacon observation path required')
    authority=tls.certificate_authority(state,expected,purpose)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.load_verify_locations(cadata=authority)
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPSHandler(context=context))
    headers={'Content-Type':'application/json'}
    if purpose=='engine':
        def b64(raw):return base64.urlsafe_b64encode(raw).decode().rstrip('=')
        header=b64(encoded({'alg':'HS256','typ':'JWT'}));claims=b64(encoded({'iat':int(time.time())}))
        message=header+'.'+claims;key=bytes.fromhex(engine.value(state,expected).decode().strip())
        headers['Authorization']='Bearer '+message+'.'+b64(hmac.digest(key,message.encode(),'sha256'))
    url=('https://127.0.0.2:8552' if purpose=='engine' else 'https://127.0.0.3:5052')+path
    request=urllib.request.Request(url,data=None if payload is None else encoded(payload),headers=headers)
    with opener.open(request,timeout=10) as response:
        require(response.status==200 and response.geturl()==url,'original peer returned an unsupported response')
        raw=response.read(1024*1024+1);require(len(raw)<=1024*1024,'original peer response exceeds its bound')
        return unique(raw)


def rpc(state,expected,method,params):
    require(method in ('eth_chainId','eth_syncing','eth_getBlockByNumber'),'unsupported validator health query')
    value=fetch(state,expected,'engine','/',{'jsonrpc':'2.0','id':1,'method':method,'params':params})
    require(isinstance(value,dict) and value.get('jsonrpc')=='2.0' and type(value.get('id'))is int and value['id']==1 and 'result' in value and 'error' not in value,
            'original execution peer rejected the observation')
    return value['result']


def hexadecimal(value):
    require(isinstance(value,str) and re.fullmatch('0x[a-fA-F0-9]{1,16}',value),'invalid original execution number')
    return int(value,16)


def synchronized_clock():
    require(run(['/usr/bin/timedatectl','show','--property=NTPSynchronized','--value']).strip()==b'yes','host clock is not synchronized')


def readiness(state,expected,now=None):
    require(expected['network'] in CHAIN_IDS,'unsupported validator network')
    synchronized_clock()
    require(hexadecimal(rpc(state,expected,'eth_chainId',[]))==CHAIN_IDS[expected['network']], 'execution network differs')
    require(rpc(state,expected,'eth_syncing',[]) is False,'original execution peer is still synchronizing')
    genesis=fetch(state,expected,'beacon','/eth/v1/beacon/genesis')['data']
    require(genesis['genesis_validators_root']==custody.ROOTS[expected['network']]
            and isinstance(genesis.get('genesis_time'),str) and re.fullmatch('[0-9]{1,12}',genesis['genesis_time']),
            'original consensus genesis differs')
    sync=fetch(state,expected,'beacon','/eth/v1/node/syncing')['data']
    require(all(sync.get(name) is False for name in ('is_syncing','is_optimistic','el_offline'))
            and sync.get('sync_distance')=='0' and isinstance(sync.get('head_slot'),str) and re.fullmatch('[0-9]{1,12}',sync['head_slot']),
            'consensus or execution is not ready for signing')
    clock=time.time() if now is None else now
    slot=int((clock-int(genesis['genesis_time']))//12)
    require(slot>=0 and abs(slot-int(sync['head_slot']))<=3,'original beacon head is stale or the host clock is wrong')
    head=rpc(state,expected,'eth_getBlockByNumber',['latest',False])
    require(isinstance(head,dict) and isinstance(head.get('hash'),str) and re.fullmatch('0x[a-fA-F0-9]{64}',head['hash'])
            and abs(clock-hexadecimal(head.get('timestamp')))<120,'original execution head is stale or the host clock is wrong')
    return {'ready':True,'head_slot':sync['head_slot'],'execution_block':head.get('number')}


def validator(state,expected,pubkey):
    require(isinstance(pubkey,str) and re.fullmatch('0x[a-f0-9]{96}',pubkey),'invalid original validator public key')
    try:
        value=fetch(state,expected,'beacon','/eth/v1/beacon/states/head/validators/'+pubkey)['data']
        require(isinstance(value,dict) and value.get('validator',{}).get('pubkey')==pubkey,'original beacon validator identity differs')
        return value
    except urllib.error.HTTPError as error:
        if error.code==404:return None
        raise


def wait_ready(state,expected,revalidate,timeout=600):
    deadline=time.monotonic()+timeout
    while True:
        # Original lease/account/history failures never become a retryable sync
        # error. No signer secret is granted while readiness is unresolved.
        revalidate()
        try:return readiness(state,expected)
        except Exception:
            require(time.monotonic()<deadline,'original authenticated supporting clients remain unavailable')
        time.sleep(min(5,max(0,deadline-time.monotonic())))

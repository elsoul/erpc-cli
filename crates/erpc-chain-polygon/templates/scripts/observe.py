# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Bounded read-only local observations of both chains and their parent transport."""
import base64
import datetime
import hashlib
import json
import os
import re
import socket
import time
import urllib.error
import urllib.request
from state import unique

LIMIT=16*1024*1024


class LocalOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,message,headers,newurl):
        fp.close()
        raise ValueError('fixed loopback observations cannot follow redirects')


def http(port,path='/',payload=None,opener=None):
    if port not in (8545,9545,1317,26657) or path not in ('/','/status','/chainmanager/params'):
        raise ValueError('unsupported fixed local observation')
    data=None if payload is None else json.dumps(payload).encode()
    request=urllib.request.Request('http://127.0.0.1:'+str(port)+path,data=data,headers={'Content-Type':'application/json'})
    open_request=opener or urllib.request.build_opener(urllib.request.ProxyHandler({}),LocalOnly()).open
    try:response=open_request(request,timeout=8)
    except urllib.error.HTTPError as error:
        error.close()
        raise ValueError('fixed local HTTP observation failed') from None
    with response:
        raw=response.read(LIMIT+1)
    if len(raw)>LIMIT:raise ValueError('local response exceeded its bound')
    value=json.loads(raw,object_pairs_hook=unique)
    if not isinstance(value,dict):raise ValueError('local API did not return an object')
    return value


def rpc(port,method,params=None,query=http):
    if method not in ('eth_chainId','eth_getBlockByNumber','eth_blockNumber','eth_syncing','net_peerCount','web3_clientVersion'):
        raise ValueError('unsupported read-only health request')
    value=query(port,payload={'jsonrpc':'2.0','id':1,'method':method,'params':params or []})
    if value.get('jsonrpc')!='2.0' or type(value.get('id')) is not int or value['id']!=1 or 'error' in value or 'result' not in value:
        raise ValueError('local JSON-RPC response binding failed')
    return value['result']


def number(value):
    if not isinstance(value,str) or len(value)>66 or not re.fullmatch('0x(?:0|[1-9a-f][a-f0-9]*)',value):
        raise ValueError('invalid hexadecimal quantity')
    return int(value,16)


def timestamp(value):
    if not isinstance(value,str) or len(value)>64:raise ValueError('invalid Heimdall block time')
    value=re.sub(r'(\.\d{6})\d+(?=Z|[+-]\d\d:\d\d$)',r'\1',value)
    observed=datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
    if observed.tzinfo is None:raise ValueError('block time must include its timezone')
    return observed.timestamp()


def heimdall(profile,query=http):
    value=query(26657,'/status').get('result',{})
    node,sync=value.get('node_info',{}),value.get('sync_info',{})
    if node.get('network')!=profile['heimdall_chain_id']:
        raise ValueError('Heimdall reports another chain identity')
    height=sync.get('latest_block_height')
    if not isinstance(height,str) or len(height)>20 or not height.isdigit() or int(height)<profile['heimdall_initial_height']:
        raise ValueError('Heimdall has not loaded the migrated network')
    age=time.time()-timestamp(sync.get('latest_block_time'))
    params=query(1317,'/chainmanager/params').get('params',{}).get('chain_params',{})
    if params.get('heimdall_chain_id')!=profile['heimdall_chain_id'] or params.get('bor_chain_id')!=str(profile['chain_id']):
        raise ValueError('Heimdall REST chain-manager state belongs to another network')
    return {'height':int(height),'age_seconds':age,'caught_up':sync.get('catching_up') is False,
            'ready':sync.get('catching_up') is False and -30<=age<=120,'node_id':node.get('id')}


def bor(profile,query=http):
    if rpc(8545,'eth_chainId',query=query)!=hex(profile['chain_id']):raise ValueError('Bor chain ID differs')
    genesis=rpc(8545,'eth_getBlockByNumber',['0x0',False],query)
    if not isinstance(genesis,dict) or genesis.get('hash')!=profile['bor_genesis_hash']:
        raise ValueError('Bor genesis differs')
    block=rpc(8545,'eth_getBlockByNumber',['latest',False],query)
    height=number(block.get('number'));age=time.time()-number(block.get('timestamp'))
    syncing=rpc(8545,'eth_syncing',query=query)
    peers=number(rpc(8545,'net_peerCount',query=query))
    version=rpc(8545,'web3_clientVersion',query=query)
    wanted=profile['releases']['bor']['tag']
    valid=isinstance(version,str) and re.match(r'^bor/'+re.escape(wanted)+r'(?:[-/]|$)',version,re.I) is not None
    return {'height':height,'age_seconds':age,'peers':peers,'client_version':version,
            'ready':height>0 and syncing is False and peers>0 and -30<=age<=120 and valid}


def parent(profile,query=http):
    wanted='0x1' if profile['parent']=='mainnet' else '0xaa36a7'
    if rpc(9545,'eth_chainId',query=query)!=wanted:raise ValueError('parent proxy reports another chain')
    # The proxy has already authenticated chain ID + genesis against the fixed
    # shared parent metadata; this additional read detects a stale provider tip.
    block=rpc(9545,'eth_getBlockByNumber',['latest',False],query)
    age=time.time()-number(block.get('timestamp'))
    if number(block.get('number'))==0 or not -30<=age<=180:
        raise ValueError('parent execution provider is stale or unavailable')
    return {'height':number(block['number']),'age_seconds':age}


def websocket(chain_id,connect=socket.create_connection):
    # One RFC6455 JSON-RPC request to the fixed local WS listener. Never follows
    # redirects or negotiates compression; no provider URL or secret is involved.
    with connect(('127.0.0.1',8546),timeout=8) as stream:
        key=base64.b64encode(os.urandom(16)).decode()
        stream.sendall(('GET / HTTP/1.1\r\nHost: 127.0.0.1:8546\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: '+key+'\r\n\r\n').encode())
        header=b''
        while not header.endswith(b'\r\n\r\n') and len(header)<8192:
            part=stream.recv(1)
            if not part:raise ValueError('WebSocket handshake closed')
            header+=part
        lines=header.decode('ascii').split('\r\n')
        if not header.endswith(b'\r\n\r\n') or not lines[0].startswith('HTTP/1.1 101 '):raise ValueError('WebSocket upgrade was refused')
        fields={}
        for line in lines[1:]:
            if not line:continue
            name,value=line.split(':',1);name=name.lower()
            if name in fields:raise ValueError('ambiguous WebSocket handshake')
            fields[name]=value.strip()
        accept=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        if fields.get('sec-websocket-accept')!=accept or fields.get('upgrade','').lower()!='websocket' or 'upgrade' not in [item.strip() for item in fields.get('connection','').lower().split(',')]:
            raise ValueError('WebSocket accept binding failed')
        body=b'{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
        mask=os.urandom(4)
        stream.sendall(bytes([0x81,0x80|len(body)])+mask+bytes(value^mask[index%4] for index,value in enumerate(body)))
        def exact(size):
            value=b''
            while len(value)<size:
                part=stream.recv(size-len(value))
                if not part:raise ValueError('incomplete WebSocket response')
                value+=part
            return value
        flags,length=exact(2)
        if flags!=0x81 or length&0x80:raise ValueError('unsupported WebSocket frame')
        if length==126:length=int.from_bytes(exact(2),'big')
        elif length==127:length=int.from_bytes(exact(8),'big')
        if not 0<length<=16384:raise ValueError('oversized WebSocket response')
        value=json.loads(exact(length),object_pairs_hook=unique)
        return value.get('jsonrpc')=='2.0' and type(value.get('id')) is int and value['id']==1 and 'error' not in value and value.get('result')==hex(chain_id)


def status(profile,query=http,sleep=time.sleep,ws=websocket):
    def sample(function):
        try:
            result=function(profile,query)
            result['available']=True
            return result
        except Exception:
            # Never include response bodies/provider credential data in a
            # progress report. Other clients still report their own progress.
            return {'available':False,'ready':False,'error':'local observation unavailable or mismatched'}
    first={name:sample(function) for name,function in [('heimdall',heimdall),('bor',bor)]}
    sleep(3)
    latest={name:sample(function) for name,function in [('heimdall',heimdall),('bor',bor)]}
    for name in latest:
        latest[name]['advancing']=(first[name]['available'] and latest[name]['available']
            and latest[name]['height']>first[name]['height'])
    upstream=sample(parent)
    private=profile.get('validator',{}).get('phase') in ('observing','active')
    if private and ws is None:websocket_ready=None
    else:
        try:websocket_ready=ws(profile['chain_id'])
        except Exception:websocket_ready=False
    advancing=all(value['advancing'] for value in latest.values())
    ready=all(value.get('ready',False) for value in latest.values()) and advancing and (websocket_ready is True or private and websocket_ready is None) and upstream['available']
    return {**latest,'parent':upstream,'advancing':advancing,'websocket_ready':websocket_ready,'ready':ready}


class ValidatorQuery:
    """Read-only health paths over original Unix peers or private-CA HTTPS."""
    def __init__(self,state,installed,connection=None,admission=False):
        import http.client
        import local_tls
        if type(admission) is not bool:raise ValueError('invalid read-only admission scope')
        self.admission=admission
        self.state,self.installed=state,installed
        self.expected=installed['contract']
        if self.expected.get('role')!='validator':raise ValueError('private validator observation requires its original role')
        state.ownership(self.expected);state.accounts.verify(self.expected)
        saved=state.read(local_tls.RECORD)
        ca=state.protected('/etc/polygon/local-ca.pem').read_bytes()
        if (saved.get('contract')!=self.expected or len(ca)>16384
                or hashlib.sha256(ca).hexdigest()!=saved.get('ca_sha256')):
            raise ValueError('validator observation has no matching original issuer')
        self.context=local_tls.client_context(ca.decode())
        self.connection=connection or http.client.HTTPSConnection

    def __call__(self,port,path='/',payload=None):
        import native_authority
        import native_peer
        paths=('/','/status','/chainmanager/params')+(('/stake/validators-set',) if self.admission else ())
        if port not in (8545,9545,1317,26657) or path not in paths:
            raise ValueError('unsupported fixed validator observation')
        if port in (8545,9545):
            if (path!='/' or not isinstance(payload,dict) or set(payload)!={'jsonrpc','id','method','params'}
                    or payload['jsonrpc']!='2.0' or type(payload['id']) is not int or payload['id']!=1
                    or payload['method'] not in ('eth_chainId','eth_getBlockByNumber','eth_blockNumber','eth_syncing','net_peerCount','web3_clientVersion')+
                        (('eth_call','eth_getBalance') if self.admission and port==9545 else ())
                    or not isinstance(payload['params'],list)):
                raise ValueError('validator health request is not a closed read-only method')
        elif payload is not None or path not in (('/status',) if port==26657 else
                ('/chainmanager/params','/stake/validators-set') if self.admission else ('/chainmanager/params',)):
            raise ValueError('validator native health path is not qualified')
        component={8545:'bor',9545:'parent',1317:'heimdall',26657:'heimdall'}[port]
        before=self.state.proof.listener(component,self.installed)
        def prove():return native_authority.read(self.state,self.expected,component,self.installed['helpers'],self.installed['profile_sha256'])
        def decode(raw):
            if len(raw)>LIMIT:raise ValueError('validator observation exceeds its bound')
            value=json.loads(raw,object_pairs_hook=unique)
            if not isinstance(value,dict):raise ValueError('validator observation did not return an object')
            return value
        if port==8545:
            result=native_peer.rpc('bor',prove,json.dumps(payload,separators=(',',':')).encode(),decode)
        elif port==1317:
            status,raw=native_peer.rest(path,prove)
            if status!=200:raise ValueError('native validator REST observation failed')
            result=decode(raw)
        else:
            address='127.0.0.10' if port==9545 else '127.0.0.13'
            client=self.connection(address,port,timeout=8,context=self.context)
            try:
                body=None if payload is None else json.dumps(payload,separators=(',',':')).encode()
                client.request('POST' if payload is not None else 'GET',path,body=body,
                    headers={'Content-Type':'application/json','Connection':'close'})
                response=client.getresponse()
                if response.status!=200:raise ValueError('private validator TLS observation failed')
                result=decode(response.read(LIMIT+1))
            finally:client.close()
        if self.state.proof.listener(component,self.installed)!=before:
            raise ValueError('original validator dependency changed during observation')
        return result

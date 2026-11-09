#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Apply narrow RPC-node overrides to complete authenticated upstream TOML."""
import ipaddress
import json
import math
import re


def scalar(value):
    if type(value) is bool:return 'true' if value else 'false'
    if type(value) is int:return str(value)
    if type(value) is float and math.isfinite(value):return repr(value)
    if isinstance(value,str):return json.dumps(value,ensure_ascii=False)
    if isinstance(value,list):return '['+', '.join(scalar(item) for item in value)+']'
    raise ValueError('unsupported value in reviewed upstream TOML')


def toml(value):
    lines=[]
    def table(mapping,path):
        if not isinstance(mapping,dict):raise ValueError('invalid configuration table')
        if path:lines.extend(['','['+'.'.join(json.dumps(part) for part in path)+']'])
        for key,item in mapping.items():
            if not isinstance(key,str):raise ValueError('non-string configuration key')
            if not isinstance(item,dict):lines.append(json.dumps(key)+' = '+scalar(item))
        for key,item in mapping.items():
            if isinstance(item,dict):table(item,path+[key])
    table(value,[])
    rendered='\n'.join(lines)+'\n'
    return rendered


def profiles(profile, bor, consensus, app, advertise, allowed,validator=None):
    network=profile['network']
    if network not in ('mainnet','amoy') or bor.get('chain')!=network or app.get('custom',{}).get('chain')!=network:
        raise ValueError('complete upstream configuration belongs to another network')
    address=ipaddress.ip_address(advertise)
    if not allowed(address):
        raise ValueError('advertised sentry address must be globally routable')
    public='['+str(address)+']' if address.version==6 else str(address)
    bor.update(datadir='/var/lib/polygon/bor/data',syncmode='full',gcmode='full')
    # Bor's Go tags name literal dotted keys. Amoy's published template uses
    # nested dotted syntax; normalize only these reviewed fields explicitly.
    for section,key,value in [('db','engine','pebble'),('state','scheme','path')]:
        nested=bor.get(section)
        if isinstance(nested,dict):
            nested.pop(key,None)
            if not nested:bor.pop(section)
        bor[section+'.'+key]=value
    bor.setdefault('p2p',{}).update(port=30303,nodekey='/run/credentials/polygon-bor.service/bor-nodekey',nat='extip:'+str(address))
    bor.setdefault('heimdall',{}).update(url='http://127.0.0.1:1317',timeout='30s')
    bor.setdefault('miner',{})['mine']=False
    bor.setdefault('accounts',{}).update(unlock=[],**{'allow-insecure-unlock':False,'disable-bor-wallet':True})
    rpc=bor.setdefault('jsonrpc',{})
    rpc['ipcdisable']=True
    modules=['eth','net','web3','txpool','bor']
    rpc.setdefault('http',{}).update(enabled=True,host='::',port=8545,api=modules,vhosts=['*'],corsdomain=[])
    rpc.setdefault('ws',{}).update(enabled=True,host='::',port=8546,api=modules,origins=[])
    rpc.setdefault('graphql',{})['enabled']=False
    bor.setdefault('telemetry',{}).update(metrics=True,**{'prometheus-addr':'[::]:7071'})
    bor.setdefault('pprof',{})['pprof']=False
    bor.setdefault('grpc',{})['addr']='127.0.0.1:3131'
    consensus.update(moniker='erpc-polygon-'+network,
        genesis_file='/var/lib/polygon/genesis/'+network+'.json',
        priv_validator_key_file='config/priv_validator_key.json',
        priv_validator_state_file='data/priv_validator_state.json',
        node_key_file='config/node_key.json')
    consensus.setdefault('rpc',{}).update(laddr='tcp://127.0.0.1:26657',unsafe=False,
        cors_allowed_origins=[],pprof_laddr='',enable_consensus_endpoints=False)
    consensus.setdefault('p2p',{}).update(laddr='tcp://[::]:26656',external_address=public+':26656',
        addr_book_file='data/addrbook.json',upnp=False,allow_duplicate_ip=False)
    consensus.setdefault('statesync',{})['enable']=False
    consensus.setdefault('instrumentation',{}).update(prometheus=True,prometheus_listen_addr=':26660')
    app.setdefault('api',{}).update(enable=True,address='tcp://127.0.0.1:1317',swagger=False)
    app.setdefault('grpc',{}).update(enable=True,address='127.0.0.1:9090')
    app.setdefault('grpc-web',{})['enable']=False
    app['custom'].update(eth_rpc_url='http://127.0.0.1:9545',bor_rpc_url='http://127.0.0.1:8545',
        bor_grpc_flag='false',comet_bft_rpc_url='http://127.0.0.1:26657')
    # Preserve protocol parameters, pruning and network peers from their pins.
    # The separate validator path supplies the immutable public signer and
    # explicit sentries. RPC callers never activate accounts or bridge settings.
    if validator is not None:validator_policy(bor,consensus,app,validator,allowed)
    return tuple(toml(value) for value in (bor,consensus,app))


def validator_peers(value,allowed):
    if (not isinstance(value,dict) or set(value)!={'signer','sentries','phase'}
            or value['phase'] not in ('observing','active')
            or not isinstance(value['signer'],str) or not re.fullmatch('0x[a-f0-9]{40}',value['signer'])
            or int(value['signer'],16)==0 or not isinstance(value['sentries'],list)
            or not 1<=len(value['sentries'])<=8):
        raise ValueError('validator native configuration requires its public phase and sentries')
    peers=[];heimdall=[];networks=[];seen=set()
    for peer in value['sentries']:
        if (not isinstance(peer,dict) or set(peer)!={'address','bor_node_id','heimdall_node_id'}
                or not isinstance(peer['bor_node_id'],str) or not re.fullmatch('[a-f0-9]{128}',peer['bor_node_id'])
                or not isinstance(peer['heimdall_node_id'],str) or not re.fullmatch('[a-f0-9]{40}',peer['heimdall_node_id'])):
            raise ValueError('invalid native sentry peer identity')
        address=ipaddress.ip_address(peer['address'])
        if not allowed(address) or address in seen:raise ValueError('sentries must be distinct reviewed public addresses')
        seen.add(address)
        host='['+str(address)+']' if address.version==6 else str(address)
        peers.append('enode://'+peer['bor_node_id']+'@'+host+':30303')
        heimdall.append(peer['heimdall_node_id']+'@'+host+':26656')
        networks.append(str(address)+('/32' if address.version==4 else '/128'))
    return peers,heimdall,networks


def validator_policy(bor,consensus,app,value,allowed):
    peers,heimdall,networks=validator_peers(value,allowed)
    active=value['phase']=='active'
    bor['miner'].update(mine=active,etherbase=value['signer'])
    bor['keystore']='/run/erpc-polygon-validator/bor-keystore'
    bor['accounts'].update(unlock=[value['signer']] if active else [],
        password='/run/credentials/polygon-bor.service/bor-password' if active else '',
        **{'allow-insecure-unlock':active,'disable-bor-wallet':True})
    bor['p2p'].update(nodiscover=True,netrestrict=','.join(networks))
    bor['p2p']['discovery']={'v4disc':False,'v5disc':False,'bootnodes':[],
        'bootnodesv4':[],'bootnodesv5':[],'dns':[],'static-nodes':peers,'trusted-nodes':peers}
    # The hot validator's native RPC is Unix-only. Its HTTPS adapter checks
    # the connected original native UID/PID before forwarding any bytes. A
    # different loopback SAN per authority prevents one native leaf certificate
    # from impersonating the funded Ethereum parent transport.
    bor['jsonrpc']['ipcdisable']=False
    bor['jsonrpc']['ipcpath']='/run/polygon-bor/native.rpc'
    bor['jsonrpc']['http'].update(enabled=False,host='127.0.0.1',vhosts=['localhost'])
    bor['jsonrpc']['ws'].update(enabled=False,host='127.0.0.1')
    bor['accounts']['allow-insecure-unlock']=False
    bor['heimdall']['url']='https://127.0.0.12:1317'
    app['api']['address']='unix:///run/polygon-heimdall/native.rest'
    app['custom'].update(eth_rpc_url='https://127.0.0.10:9545',
        bor_rpc_url='https://127.0.0.11:8545',comet_bft_rpc_url='https://127.0.0.13:26657',
        heimdall_rest_server='https://127.0.0.12:1317')
    consensus['rpc'].update(laddr='tcp://127.0.0.13:26657',
        tls_cert_file='/run/credentials/polygon-heimdall.service/comet-certificate',
        tls_key_file='/run/credentials/polygon-heimdall.service/comet-private-key')
    consensus['p2p'].update(seeds='',persistent_peers=','.join(heimdall),pex=False,external_address='')
    consensus['priv_validator_state_file']='data/priv_validator_state.json' if active else 'data/priv_validator_observer_state.json'
    # Native helper.InitHeimdallConfig independently reads the fixed home key
    # file. A phase-bound encrypted projection feeds that same credential to
    # both helper and Comet; observers never receive the original hot key.
    consensus['priv_validator_key_file']='config/priv_validator_key.json'
    # No credential enters this public manifest. Active native startup uses
    # --app with the encrypted systemd credential containing the local AMQP URL.
    app['custom']['amqp_url']=''
    app['custom']['main_chain_gas_fee_cap']='500000000000'
    app['custom']['main_chain_gas_tip_cap']='10000000000'


def client(profile):
    chain=profile.get('heimdall_chain_id')
    if chain not in ('heimdallv2-137','heimdallv2-80002'):
        raise ValueError('unsupported Heimdall client chain identity')
    # Cosmos client initialization eagerly opens this keyring even for server
    # commands. RPC nodes have no financial account; memory avoids OS wallet
    # services and creates no persistent funding/signing account.
    return toml({'chain-id':chain,'keyring-backend':'memory','output':'text',
                 'node':'tcp://127.0.0.1:26657','broadcast-mode':'sync'})

#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Public native admission observations; no financial signer or transaction RPC.

The actual kcn/kpn executables select native node roles. Kaia's TOML worker
switch and NodeTypeFlag are not registered runtime configuration in this pin.
The native consensus engine remains responsible for qualified participation.
"""
import ipaddress
import json
import re
import socket
import stat
import struct


def address(value):return isinstance(value,str) and re.fullmatch('0x[a-fA-F0-9]{40}',value) is not None

def validate(c,value):
    c.require(value.get('node_kind') in ('cn','pn'),'unsupported core-cell kind')
    try:ip=ipaddress.IPv4Address(value.get('advertise'))
    except Exception:raise c.Refused('core-cell advertisement requires numeric IPv4') from None
    c.require(not(ip.is_loopback or ip.is_multicast or ip.is_link_local or ip.is_unspecified) and 0<int(ip)<0xe0000000 and ip.packed[0]!=0,
              'unsupported core-cell advertisement')
    peers=value.get('peers')
    c.require(isinstance(peers,list) and (len(peers)==0 or 2<=len(peers)<=64),'bounded approved static peers are required')
    identities=set();routes=set();kinds=set()
    for peer in peers:
        c.require(isinstance(peer,str) and len(peer)<=256,'invalid core-cell peer')
        match=re.fullmatch(r'kni://([a-f0-9]{128})@([0-9.]+):([0-9]{1,5})\?discport=0&ntype=(cn|pn)',peer)
        c.require(match is not None,'core-cell peer requires the documented KNI shape')
        key,host,port,kind=match.groups()
        try:ip=ipaddress.IPv4Address(host)
        except Exception:raise c.Refused('core-cell peer requires numeric IPv4') from None
        c.require(0<int(port)<65536 and not(ip.is_loopback or ip.is_multicast or ip.is_link_local) and
                  0<int(ip)<0xe0000000 and ip.packed[0]!=0,'unsupported core-cell peer route')
        c.require(key not in identities and (host,int(port)) not in routes,'repeated core-cell identity or route')
        identities.add(key);routes.add((host,int(port)));kinds.add(kind)
    c.require(not peers or kinds=={'cn','pn'},'approved topology requires both CN and PN peers')
    if value['node_kind']=='cn':
        c.require(value.get('storage')=='full','qualified CN operation requires full retention')
        c.require(all(address(value.get(key)) and int(value[key],16)>0 for key in ('reward_address','manager_address')),
                  'external reward and manager public addresses are required')
    else:c.require(not any(value.get(key) for key in ('reward_address','manager_address','staking_address')) and value.get('gc_id')=='0',
                   'PN hosts cannot carry financial registration authority')
    staking=value.get('staking_address')
    c.require(staking=='' or (address(staking) and int(staking,16)>0),'invalid external staking address')
    gc=value.get('gc_id')
    c.require(isinstance(gc,str) and re.fullmatch('0|[1-9][0-9]{0,77}',gc) and int(gc)<2**256,'invalid assigned GC ID')


def configuration(c,state):
    validate(c,state)
    c.require(len(state['peers'])>=2,'enroll the original public URI and configure approved CN/PN peers before deployment')
    public=state.get('custody_public',{})
    c.require(not public.get('address') or public['address'] not in (state['reward_address'],state['manager_address']),
              'financial authorities must remain separate from the original consensus identity')
    c.require(public.get('peer_key') not in [peer[6:134] for peer in state['peers']],'core-cell cannot peer with itself')
    return json.dumps(state['peers'],separators=(',',':')).encode()


def ipc(c,state,method,params):
    c.require(method in ('admin_nodeInfo','istanbul_getValidators','istanbul_getDemotedValidators'),
              'unsupported read-only core-cell observation')
    c.require(isinstance(params,list) and (params==[] if method=='admin_nodeInfo' else
              len(params)==1 and isinstance(params[0],str) and re.fullmatch('0x[a-f0-9]{1,16}',params[0])),
              'invalid bounded native observation parameters')
    container=c.check_container(state)
    c.require(container is not None and container.get('State',{}).get('Running') is True,'owned core-cell is not running')
    pid=container['State'].get('Pid');uid=state.get('service_uid');gid=state.get('service_gid')
    c.require(all(type(value)is int and value>0 for value in (pid,uid,gid)),'original core-cell identity is unavailable')
    path=c.ROOT/'data/kaia.ipc'
    info=path.lstat()
    c.require(stat.S_ISSOCK(info.st_mode) and info.st_uid==uid,'native IPC path is not owned by the original identity')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as stream:
        stream.settimeout(10);stream.connect(str(path))
        c.require(hasattr(socket,'SO_PEERCRED'),'Linux kernel peer credentials are required')
        actual=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        c.require(actual==(pid,uid,gid),'native IPC peer differs from the original container process')
        stream.sendall(json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params},separators=(',',':')).encode()+b'\n')
        data=b''
        while b'\n' not in data:
            block=stream.recv(min(65536,1048577-len(data)))
            c.require(block and len(data)+len(block)<=1048576,'native IPC response is absent or oversized')
            data+=block
    def pairs(values):
        out={}
        for key,value in values:
            c.require(key not in out,'ambiguous native IPC fields');out[key]=value
        return out
    try:value=json.loads(data,object_pairs_hook=pairs,parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except Exception:raise c.Refused('invalid native IPC observation') from None
    c.require(isinstance(value,dict) and value.get('jsonrpc')=='2.0' and type(value.get('id'))is int and
              value['id']==1 and 'error' not in value and 'result' in value,'native IPC observation failed')
    latest=c.check_container(state)
    c.require(latest is not None and latest.get('Id')==container.get('Id') and
              all(latest.get('State',{}).get(key)==container['State'].get(key) for key in ('Running','Pid','StartedAt')),
              'container identity changed during IPC observation')
    after=path.lstat()
    c.require((after.st_dev,after.st_ino)==(info.st_dev,info.st_ino),'native IPC path changed during observation')
    return value['result']


def observe(c,state,base):
    """Observe one bounded local canonical block after caller proves its owner.

    Council authorization is not permissionless admission. GC allocation and
    manager authority remain externally administered; this report never treats
    a supplied GC ID as on-chain proof or calculates policy from a stake guess.
    """
    result={'node_kind':state['node_kind'],'native_participation':'proxy' if state['node_kind']=='pn' else 'native qualified-membership checks',
            'financial_transactions':'disabled','manager_authority':'external','gc_id':state['gc_id'],
            'admission_observed':False,'qualified_observed':False,'staking_observed':False,'gc_id_observed':False,'bls_observed':False}
    if base.get('ready') is not True:return result
    public=state.get('custody_public',{})
    own=public.get('address','').lower();number=base['block']
    before=c.check_container(state)
    c.require(before is not None and before.get('State',{}).get('Running') is True and c.owned_ports(before['State'].get('Pid'),(8551,8552)),
              'owned admission observer is unavailable')
    live=ipc(c,state,'admin_nodeInfo',[])
    c.require(isinstance(live,dict) and isinstance(live.get('nodeAddress'),str) and live['nodeAddress'].lower()==own and
              live.get('blsPublicKeyInfo')=={'publicKey':public.get('bls_key'),'pop':public.get('bls_pop')},
              'running core-cell identity differs from its sealed original')
    result['native_identity_verified']=True
    if state['node_kind']=='pn':return result
    first=c.rpc('eth_getBlockByNumber',[number,False])
    c.require(isinstance(first,dict) and isinstance(first.get('hash'),str) and re.fullmatch('0x[a-fA-F0-9]{64}',first['hash']),
              'bounded admission block is unavailable')
    qualified=ipc(c,state,'istanbul_getValidators',[number])
    c.require(isinstance(qualified,list) and len(qualified)<=4096 and all(address(x) for x in qualified) and
              len(set(x.lower() for x in qualified))==len(qualified),'malformed native qualified validator observation')
    council=c.rpc('kaia_getCouncil',[number])
    c.require(isinstance(council,list) and len(council)<=4096 and all(address(x) for x in council) and
              len(set(x.lower() for x in council))==len(council),'malformed council observation')
    info=c.rpc('kaia_getStakingInfo',[number])
    names=('councilNodeAddrs','councilStakingAddrs','councilRewardAddrs','councilStakingAmounts')
    c.require(isinstance(info,dict) and all(isinstance(info.get(key),list) for key in names),'staking observation is unavailable')
    length=len(info[names[0]])
    c.require(length<=4096 and all(len(info[key])==length for key in names),'staking observation is inconsistent')
    c.require(all(address(item) for key in names[:3] for item in info[key]) and
              all(type(item)is int and 0<=item<2**64 for item in info[names[3]]),'invalid staking observation fields')
    rows=[index for index,value in enumerate(info[names[0]]) if value.lower()==own]
    c.require(len(rows)<=1,'ambiguous staking identity')
    staking=False;gc_verified=False
    if rows:
        index=rows[0]
        staking=((state['staking_address']=='' or info[names[1]][index].lower()==state['staking_address'].lower()) and
                 info[names[2]][index].lower()==state['reward_address'].lower())
        result['reported_stake_kaia']=info[names[3]][index]
        result['staking_address']=info[names[1]][index]
        if staking:
            # Solidity public getters in pinned CnStakingV3Storage. No mutable
            # contract method, signing key or transaction submission is used.
            observed=[]
            for selector in ('0x6d2714db','0x139d7fed'):
                value=c.rpc('eth_call',[{'to':info[names[1]][index],'data':selector},number])
                c.require(isinstance(value,str) and re.fullmatch('0x[a-fA-F0-9]{64}',value),'native staking getter returned an invalid ABI word')
                observed.append(value)
            gc=str(int(observed[0],16));result['onchain_gc_id']=gc
            gc_verified=gc!='0' and gc==state['gc_id'] and int(observed[1],16)==int(own,16)
    bls=c.rpc('kaia_getBlsInfos',[number])
    c.require(isinstance(bls,dict) and len(bls)<=4096 and all(address(key) for key in bls),'malformed BLS registry observation')
    entries=[value for key,value in bls.items() if key.lower()==own]
    c.require(len(entries)<=1,'ambiguous BLS registry identity')
    entry=entries[0] if entries else None
    valid_bls=isinstance(entry,dict) and set(entry)=={'publicKey','pop','verifyErr'} and entry.get('verifyErr') is None and entry.get('publicKey')==public.get('bls_key') and entry.get('pop')==public.get('bls_pop')
    last=c.rpc('eth_getBlockByNumber',[number,False]);after=c.check_container(state)
    c.require(isinstance(last,dict) and last.get('hash')==first['hash'] and before is not None and after is not None and
              before.get('Id')==after.get('Id') and all(before.get('State',{}).get(key)==after.get('State',{}).get(key) for key in ('Running','Pid','StartedAt')),
              'owned process or canonical admission block changed')
    c.require(c.owned_ports(after['State'].get('Pid'),(8551,8552)),'admission listener identity changed')
    result.update(admission_observed=own in [x.lower() for x in council],qualified_observed=own in [x.lower() for x in qualified],staking_observed=staking,gc_id_observed=gc_verified,bls_observed=valid_bls,
                  observed_block=number,observed_hash=first['hash'])
    return result


def publish_configuration(c,state):
    data=configuration(c,state)
    c.protected_directory(c.CONF)
    for name,raw in (('static-nodes.json',data),('trusted-nodes.json',b'[]')):publish(c,name,raw)


def publish(c,name,data):
    path=c.CONF/name;temporary=c.CONF/(name+'.new')
    c.protected_file(path);c.protected_file(temporary)
    temporary.unlink(missing_ok=True)
    fd=c.os.open(temporary,c.os.O_CREAT|c.os.O_EXCL|c.os.O_NOFOLLOW|c.os.O_WRONLY,0o644)
    with c.os.fdopen(fd,'wb') as stream:
        stream.write(data);stream.flush();c.os.fchmod(stream.fileno(),0o644);c.os.fsync(stream.fileno())
    c.os.replace(temporary,path)
    descriptor=c.os.open(c.CONF,c.os.O_DIRECTORY)
    try:c.os.fsync(descriptor)
    finally:c.os.close(descriptor)

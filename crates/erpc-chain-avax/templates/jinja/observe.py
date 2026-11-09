# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fixed local public observations bound to the original native process/socket."""
import hashlib
import http.client
import json
import os
import pathlib
import re
import stat


def owned_process(c,expected,unit):
    record=c.account(expected)
    def value(name):return c.command('systemctl','show','--property='+name,'--value',unit).stdout.decode().strip()
    c.require(value('User')==str(record['service_uid']) and value('Group')==str(record['service_gid']) and value('SupplementaryGroups')=='','loaded native recipient differs')
    c.require(value('ActiveState')=='active','original Avalanche native service is not active')
    pid=value('MainPID');c.require(pid.isdecimal() and int(pid)>0,'native MainPID is unavailable')
    group=value('ControlGroup');c.require(group=='/system.slice/'+unit,'native control group differs')
    root=c.path('/proc/'+pid);info=root.lstat()
    c.require(stat.S_ISDIR(info.st_mode) and info.st_uid==record['service_uid'],'native process belongs to another UID')
    status={line.split(':',1)[0]:line.split(':',1)[1].split() for line in (root/'status').read_text().splitlines() if ':' in line}
    c.require(status.get('Uid')==[str(record['service_uid'])]*4 and status.get('Gid')==[str(record['service_gid'])]*4 and
              set(status.get('Groups',[]))<={str(record['service_gid'])},'native process credentials differ')
    c.require('0::'+group in (root/'cgroup').read_text().splitlines(),'native process left its managed cgroup')
    raw=(root/'stat').read_text();parts=raw[raw.rfind(')')+2:].split()
    c.require(len(parts)>19 and parts[19].isdecimal(),'native process generation is unavailable')
    return root,pid,parts[19]


def process(c,expected):
    root,pid,generation=owned_process(c,expected,'avalanchego.service')
    argv=(root/'cmdline').read_bytes().rstrip(b'\x00').split(b'\x00')
    c.require(argv==[b'/opt/avalanchego/current/avalanchego',b'--config-file=/etc/avalanchego/node.json'],
              'native process arguments differ from the owned configuration')
    pointer=c.path('/opt/avalanchego/current');link=pointer.lstat()
    c.require(stat.S_ISLNK(link.st_mode) and link.st_uid==c.owner,'native release pointer changed')
    target=os.readlink(pointer)
    c.require(re.fullmatch(r'/opt/avalanchego/v1[.]15[.][0-9]+',target) is not None,'native release target is unqualified')
    binary=c.protected(target+'/avalanchego');native=binary.stat();running=(root/'exe').stat()
    c.require((running.st_dev,running.st_ino)==(native.st_dev,native.st_ino),'native executable was replaced or deleted')
    receipt=c.durable_json('/etc/avalanchego/native.json')
    c.require(receipt.get('contract')==expected and receipt.get('binary')==target+'/avalanchego' and
              receipt.get('sha256')==hashlib.sha256(binary.read_bytes()).hexdigest() and
              receipt.get('config')==hashlib.sha256(c.protected('/etc/avalanchego/node.json').read_bytes()).hexdigest(),
              'native executable or configuration differs from its completed receipt')
    owned=set()
    for fd in (root/'fd').iterdir():
        try:match=re.fullmatch(r'socket:\[([0-9]+)\]',os.readlink(fd))
        except FileNotFoundError:continue
        if match:owned.add(match.group(1))
    listeners=[]
    for name in ('tcp','tcp6'):
        path=c.path('/proc/net/'+name)
        if name=='tcp6' and not path.exists():continue
        for line in path.read_text().splitlines()[1:]:
            fields=line.split()
            c.require(len(fields)>=10,'native socket authority is unreadable')
            address,port=fields[1].split(':')
            if int(port,16)==9650 and fields[3]=='0A':listeners.append((name,address,fields[9]))
    c.require(len(listeners)==1 and listeners[0][0:2]==('tcp','0100007F') and listeners[0][2] in owned,
              'the fixed loopback RPC listener does not belong to the original native process')
    return pid,generation,native.st_dev,native.st_ino,listeners[0][2]


def gateway_process(c,expected):
    root,pid,generation=owned_process(c,expected,'avalanche-rpc.service')
    receipt=c.gateway(expected)
    # nginx 1.24 ngx_master_process_cycle + ngx_setproctitle join the original
    # argv after "nginx: master process "; only this closed managed command fits.
    title=b'nginx: master process /usr/sbin/nginx -c /etc/avalanchego/proxy.conf -g daemon off;'
    c.require((root/'cmdline').read_bytes().rstrip(b'\x00')==title,'gateway master arguments differ')
    binary=c.protected('/usr/sbin/nginx').stat();running=(root/'exe').stat()
    c.require((running.st_dev,running.st_ino)==(binary.st_dev,binary.st_ino),'gateway executable was replaced or deleted')
    owned=set()
    for fd in (root/'fd').iterdir():
        try:match=re.fullmatch(r'socket:\[([0-9]+)\]',os.readlink(fd))
        except FileNotFoundError:continue
        if match:owned.add(match.group(1))
    listeners=[]
    for name in ('tcp','tcp6'):
        path=c.path('/proc/net/'+name)
        if name=='tcp6' and not path.exists():continue
        for line in path.read_text().splitlines()[1:]:
            fields=line.split();c.require(len(fields)>=10,'gateway socket authority is unreadable')
            address,port=fields[1].split(':');port=int(port,16)
            if fields[3]=='0A' and (port in (9652,9653) or fields[9] in owned):
                listeners.append((name,address,port,fields[9]))
    wanted={(9652,receipt['rpc_bind']),(9653,receipt['metrics_bind'])}
    c.require(len(listeners)==2 and all(name=='tcp' and inode in owned for name,address,port,inode in listeners) and
              {(port,'127.0.0.1' if address=='0100007F' else '0.0.0.0' if address=='00000000' else '')
               for name,address,port,inode in listeners}==wanted,'gateway listener ownership or bindings differ')
    return pid,generation,binary.st_dev,binary.st_ino,tuple(sorted(listeners))


def gateway_observation(c,expected,native):
    try:
        before_native=process(c,expected);before=gateway_process(c,expected)
        result={}
        for name,path,method in (
            ('network','/ext/info','info.getNetworkID'),('identity','/ext/info','info.getNodeID'),
            ('health','/ext/health','health.health'),('chain_id','/ext/bc/C/rpc','eth_chainId')):
            result[name]=rpc(path,method,[] if name=='chain_id' else {},port=9652)
        result['bootstrap']={chain:rpc('/ext/info','info.isBootstrapped',{'chain':chain},port=9652) for chain in ('P','X','C')}
        c.require(process(c,expected)==before_native and gateway_process(c,expected)==before,'gateway or native process changed during gateway observation')
        c.require(native.get('authority',{}).get('verified') is True and
                  all(result[name].get('result')==native[name].get('result') for name in ('network','identity','chain_id')),
                  'gateway identity or network differs from the original native process')
        result['authority']={'verified':True,'gateway_pid':int(before[0])}
        result['rpc_bind']=c.gateway(expected)['rpc_bind']
        result['external_reachability']='not tested'
        return result
    except Exception:
        return {'authority':{'verified':False},'observations':'original gateway process, configuration, listener or HTTP unavailable',
                'external_reachability':'not tested'}


def rpc(path,method,params,port=9650):
    if port not in (9650,9652):raise ValueError('unqualified local RPC port')
    connection=http.client.HTTPConnection('127.0.0.1',port,timeout=8)
    try:
        connection.request('POST',path,json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}),
                           {'Content-Type':'application/json'})
        response=connection.getresponse()
        if response.status!=200:raise ValueError('local RPC response is not successful')
        raw=response.read(8*1024*1024+1)
        if len(raw)>8*1024*1024:raise ValueError('local RPC response exceeds its bound')
        return json.loads(raw)
    finally:connection.close()


def observe(c,expected):
    result={'authority':{'verified':False}}
    try:
        before=process(c,expected);c.verify_identity(expected)
        for name,path,method in (
            ('network','/ext/info','info.getNetworkID'),('identity','/ext/info','info.getNodeID'),
            ('health','/ext/health','health.health'),('chain_id','/ext/bc/C/rpc','eth_chainId'),
            ('head','/ext/bc/C/rpc','eth_blockNumber'),('uptime','/ext/info','info.uptime'),
            ('version','/ext/info','info.getNodeVersion')):
            result[name]=rpc(path,method,{}) if path!='/ext/bc/C/rpc' else rpc(path,method,[])
        result['bootstrap']={chain:rpc('/ext/info','info.isBootstrapped',{'chain':chain}) for chain in ('P','X','C')}
        node=result['identity'].get('result',{}).get('nodeID')
        if isinstance(node,str) and re.fullmatch('NodeID-[1-9A-HJ-NP-Za-km-z]{1,64}',node):
            result['current']=rpc('/ext/bc/P','platform.getCurrentValidators',{'nodeIDs':[node]})
        c.require(process(c,expected)==before,'native process or listener changed during observation')
        result['authority']={'verified':True,'native_pid':int(before[0])}
    except Exception:
        result={'authority':{'verified':False},'observations':'original process, identity or RPC unavailable'}
    result['gateway']=gateway_observation(c,expected,result)
    for unit in ('avalanchego','avalanche-rpc'):
        try:result[unit]=c.command('systemctl','is-active',unit,check=False).stdout.decode().strip()
        except Exception:result[unit]='unknown'
    return result

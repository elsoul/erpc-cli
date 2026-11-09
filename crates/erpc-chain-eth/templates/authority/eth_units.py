# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Numeric native units and retained process/image definitions for original RPC hosts."""
import hashlib
import json
import os
from pathlib import Path
import re
from eth_files import atomic,read,require,root_directory,synchronize
import eth_namespace as namespace

UNITS=('reth.service','lighthouse.service','reth-snapshot.service','erpc-eth-firewall.service')


def quoted(value):
    require(isinstance(value,str) and '\0' not in value and '\n' not in value and '\r' not in value,'invalid systemd argument')
    return '"'+value.replace('\\','\\\\').replace('"','\\"').replace('%','%%').replace('$','$$')+'"'


def external(revision,action,operation=None):
    require(re.fullmatch('[a-f0-9]{64}',revision) and action in ('guard','snapshot-guard','snapshot-complete','firewall-load'),
            'invalid fixed original runtime entrypoint')
    directory=namespace.PROFILES['rpc']['helpers']/'releases'/revision
    program=read(namespace.SOURCE/'eth_trust.py').decode()+"\nimport runpy,sys\n"
    program+='trusted_imports('+repr(str(directory))+')\n'
    program+='import hashlib,os\nprofile='+repr(namespace.RPC_FILES)+'\ndirectory='+repr(str(directory))+'\n'
    program+='if set(os.listdir(directory))!=set(profile):raise ValueError("immutable original helper profile differs")\n'
    program+='hasher=hashlib.sha256()\nfor name in profile:\n with open(os.path.join(directory,name),"rb") as source:\n  for block in iter(lambda:source.read(131072),b""):hasher.update(block)\n'
    program+='if hasher.hexdigest()!='+repr(revision)+':raise ValueError("immutable original helper digest differs")\n'
    program+='sys.argv=['+repr(str(directory/'control.py'))+','+repr(action)
    if operation is not None:
        require((action=='guard' and operation in UNITS[:2]) or (action.startswith('snapshot-') and re.fullmatch('[a-f0-9]{32}',operation)),
                'native guard requires its original unit or snapshot intent')
        program+=','+repr(operation)
    program+=']\nrunpy.run_path('+repr(str(directory/'control.py'))+",run_name='__main__')\n"
    inline="exec(bytes.fromhex('"+program.encode().hex()+"'))"
    return '/usr/bin/python3 -I -c '+quoted(inline)


def target(value):
    require(isinstance(value,dict) and set(value)=={'pair','artifacts','rpc_bind','metrics_bind','checkpoint'},'invalid native RPC target')
    require(isinstance(value['pair'],str) and re.fullmatch(r'reth-v[0-9][0-9A-Za-z.-]{0,80}--lighthouse-v[0-9][0-9A-Za-z.-]{0,80}',value['pair']),
            'qualified immutable client pair required')
    require(value['rpc_bind'] in ('127.0.0.1','0.0.0.0') and value['metrics_bind'] in ('127.0.0.1','0.0.0.0'),
            'RPC/metrics bind must follow the confirmed access policy')
    require(set(value['artifacts'])=={'reth','lighthouse'},'both qualified native images required')
    for record in value['artifacts'].values():
        require(set(record)=={'sha256'} and isinstance(record['sha256'],str) and re.fullmatch('[a-f0-9]{64}',record['sha256']),
                'verified native binary digest required')
    # The checkpoint is the carried network constant, never an inventory URL.
    vars_file=namespace.SOURCE/'network.yml'
    settings=read(vars_file).decode()
    match=re.search(r'^eth_checkpoint_sync_url: (\S+)$',settings,re.M)
    require(match and value['checkpoint']==match.group(1),'checkpoint differs from the carried network profile')
    return value


def native_arguments(contract,value):
    value=target(value);pair=namespace.PROFILES['rpc']['opt']/value['pair'];data=Path('/var/lib/ethereum')
    api='eth,net,web3' if contract['kind']=='full' else 'eth,net,web3,debug,trace'
    reth=[str(pair/'reth'),'--color','never','--log.file.max-files','0','node','--chain','mainnet','--datadir',str(data/'reth')]
    if contract['kind']=='full':reth+=['--full']
    reth+=['--addr','0.0.0.0','--port','30303','--discovery.port','30303','--discovery.v5.port','9200',
           '--http','--http.addr',value['rpc_bind'],'--http.port','8545','--http.api',api,
           '--ws','--ws.addr',value['rpc_bind'],'--ws.port','8546','--ws.api',api,'--ipcdisable',
           '--authrpc.addr','127.0.0.1','--authrpc.port','8551','--authrpc.jwtsecret','/etc/ethereum/jwt.hex',
           '--metrics',value['metrics_bind']+':9002']
    beacon=[str(pair/'lighthouse'),'bn','--network','mainnet','--datadir',str(data/'lighthouse'),
            '--execution-endpoint','http://127.0.0.1:8551','--execution-jwt','/etc/ethereum/jwt.hex',
            '--checkpoint-sync-url',value['checkpoint'],'--port','9000','--quic-port','9001','--disable-upnp',
            '--http','--http-address','127.0.0.1','--http-port','5052','--metrics',
            '--metrics-address',value['metrics_bind'],'--metrics-port','5054']
    snapshot=[str(pair/'reth'),'--color','never','--log.file.max-files','0','download','--chain','mainnet',
              '--datadir',str(data/'reth'),'--'+contract['kind'],'--resumable=true','--download-concurrency','8','-y']
    return {'reth.service':reth,'lighthouse.service':beacon,'reth-snapshot.service':snapshot}


def definition(name,argv,identity,revision,operation):
    require(name in UNITS[:3],'unknown original native service')
    snapshot=name=='reth-snapshot.service';data='/var/lib/ethereum/'+('lighthouse' if name=='lighthouse.service' else 'reth')
    ordering='Conflicts=reth.service lighthouse.service\n' if snapshot else 'Requires=erpc-eth-firewall.service\nAfter=erpc-eth-firewall.service\n'
    if name=='lighthouse.service':ordering+='After=reth.service\nWants=reth.service\n'
    startup=external(revision,'snapshot-guard' if snapshot else 'guard',operation if snapshot else name)
    post='ExecStartPost=+'+external(revision,'snapshot-complete',operation)+'\n' if snapshot else ''
    return ('[Unit]\nDescription=Original Ethereum '+name+'\nAfter=network-online.target\nWants=network-online.target\n'+ordering+
            '[Service]\nType='+('oneshot' if snapshot else 'simple')+'\nUser='+str(identity['uid'])+'\nGroup='+str(identity['gid'])+
            '\nUMask=0077\nWorkingDirectory='+data+'\nExecStartPre=+'+startup+'\nExecStart='+
            ' '.join(quoted(item) for item in argv)+'\n'+post+
            ('TimeoutStartSec=infinity\n' if snapshot else 'Restart=on-failure\nRestartSec=10\n')+
            'KillMode=control-group\nSendSIGKILL=no\nKillSignal=SIGINT\nSuccessExitStatus=130 143 SIGINT SIGTERM\nTimeoutStopSec=600\n'
            'LimitNOFILE=1048576\nLimitCORE=0\nStandardOutput=journal\nStandardError=journal\n'
            'ReadWritePaths='+data+' /var/lib/erpc-ethereum-authority/rpc\nReadOnlyPaths=/opt/ethereum /etc/ethereum\n'
            'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\nNoNewPrivileges=yes\nProtectSystem=strict\n'
            'ProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\n'
            'ProtectKernelLogs=yes\nProtectControlGroups=yes\nProtectClock=yes\nProtectHostname=yes\nRestrictSUIDSGID=yes\n'
            'RestrictNamespaces=yes\nRestrictRealtime=yes\nLockPersonality=yes\nCapabilityBoundingSet=\nSystemCallArchitectures=native\n'+
            ('' if snapshot else '[Install]\nWantedBy=multi-user.target\n'))


def render(contract,value,accounts,revision,operation):
    require(contract['role']=='rpc' and accounts['role']=='rpc','RPC numeric account profile required')
    arguments=native_arguments(contract,value);definitions={};processes={}
    for name,argv in arguments.items():
        client='lighthouse' if name=='lighthouse.service' else 'reth';identity=accounts['users'][client]
        definitions[name]=definition(name,argv,identity,revision,operation)
        processes.setdefault(argv[0],[]).append({'uid':identity['uid'],'gid':identity['gid'],'unit':name,'argv':argv,
                                               'sha256':value['artifacts'][client]['sha256']})
    definitions[UNITS[3]]='[Unit]\nDescription=Original Ethereum confirmed ingress\nBefore=reth.service lighthouse.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart='+external(revision,'firewall-load')+'\n[Install]\nWantedBy=multi-user.target\n'
    return {'definitions':definitions,'processes':processes,'revision':revision,'contract':contract,'intent':operation,'target':value}


def retain(state,contract,receipt):
    state.check(contract);require(receipt['contract']==contract,'unit publication belongs to another original host')
    name='units-'+receipt['intent']+'.json'
    if state.exists(name):require(state.get(name)==receipt,'original unit publication bytes differ')
    else:state.put(name,receipt)
    synchronize(state.path(name))


def installed(receipt):
    for name,text in receipt['definitions'].items():
        require(name in UNITS and read(namespace.SYSTEMD/name)==text.encode(),'installed original unit differs')


def publish(state,contract,operation,receipt):
    state.current(contract,operation);require(receipt['intent']==operation,'unit publication intent differs')
    namespace.paths('rpc');retain(state,contract,receipt)
    for name,text in receipt['definitions'].items():
        state.current(contract,operation)
        path=namespace.SYSTEMD/name
        if path.is_symlink():
            require(path.lstat().st_uid==0 and os.readlink(path)=='/dev/null','unknown unit selector cannot be replaced')
            path.unlink()
        atomic(path,text.encode(),0o644)
    installed(receipt)


def retained_processes(state,contract):
    state.check(contract);approved={};count=0
    for path in state.directory.glob('units-*.json'):
        count+=1;require(count<=4096,'retained original unit history exceeds its bound')
        receipt=state.get(path.name);require(receipt['contract']==contract,'retained unit receipt belongs to another host')
        for image,entries in receipt['processes'].items():
            for entry in entries:
                if entry not in approved.setdefault(image,[]):approved[image].append(entry)
    return approved


def stop_owned(state,contract,run,selected=('lighthouse.service','reth.service','reth-snapshot.service')):
    """Missing units never imply quiescence; the caller also drains retained PIDs."""
    state.check(contract);known={name:set() for name in UNITS};count=0
    for path in state.directory.glob('units-*.json'):
        count+=1;require(count<=4096,'retained unit history exceeds its bound')
        receipt=state.get(path.name);require(receipt['contract']==contract,'retained unit ownership differs')
        for name,text in receipt['definitions'].items():
            require(name in known,'unknown retained service');known[name].add(hashlib.sha256(text.encode()).hexdigest())
    failures=[]
    require(set(selected)<=set(UNITS[:3]),'unknown original stop scope')
    for name in selected:
        try:
            path=namespace.SYSTEMD/name
            if path.is_symlink():
                require(path.lstat().st_uid==0 and os.readlink(path)=='/dev/null','unknown unit selector cannot acquire shutdown authority')
                raw=run(['/usr/bin/systemctl','show',name,'--property=MainPID','--value'])
                require(raw.strip()==b'0','masked original service still has a writer')
                continue
            if not path.exists() and not path.is_symlink():
                raw=run(['/usr/bin/systemctl','show',name,'--property=LoadState','--value'],allowed=(0,1))
                require(raw.strip()==b'not-found','missing original definition still has a loaded unit')
                continue
            require(hashlib.sha256(read(path)).hexdigest() in known[name],'foreign unit cannot acquire shutdown authority')
            # Authenticated on-disk bytes govern ExecStop too, even if a loaded
            # unit has stale metadata. Do not reload or execute unknown files.
            namespace.paths('rpc');run(['/usr/bin/systemctl','daemon-reload'])
            run(['/usr/bin/systemctl','stop',name],timeout=660)
            raw=run(['/usr/bin/systemctl','show',name,'--property=MainPID','--value'])
            require(raw.strip()==b'0','owned native unit did not stop')
        except Exception:failures.append(name)
    require(not failures,'one or more original Ethereum units could not be stopped')


def disable_owned(state,contract,run):
    """Retirement preserves ingress and receipts, but disables owned native boot units."""
    state.check(contract);namespace.paths('rpc');known={name:set() for name in UNITS[:2]}
    for path in state.directory.glob('units-*.json'):
        receipt=state.get(path.name);require(receipt['contract']==contract,'retained service ownership differs')
        for name in known:
            if name in receipt['definitions']:known[name].add(hashlib.sha256(receipt['definitions'][name].encode()).hexdigest())
    failures=[]
    for name in known:
        path=namespace.SYSTEMD/name
        try:
            if path.is_symlink():
                require(path.lstat().st_uid==0 and os.readlink(path)=='/dev/null','unknown original unit mask');continue
            if not path.exists():
                require(run(['/usr/bin/systemctl','show',name,'--property=LoadState','--value'],allowed=(0,1)).strip()==b'not-found',
                        'missing original native unit is still loaded');continue
            require(hashlib.sha256(read(path)).hexdigest() in known[name],'unknown service cannot be disabled')
            run(['/usr/bin/systemctl','disable',name])
        except Exception:failures.append(name)
    require(not failures,'one or more original native units could not be disabled; retained state stays fenced')

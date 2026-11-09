# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Dedicated original-validator unit/argv profile; no signer secret in unit text."""
from pathlib import Path
import re
from eth_files import read,require
import eth_accounts as accounts
import eth_namespace as namespace
from eth_units import quoted

ROOT=Path('/var/lib/erpc-eth-validator')
RUN=Path('/run/erpc-eth-validator')
UNITS=('erpc-eth-execution.service','erpc-eth-engine-transport.service','erpc-eth-beacon.service',
       'erpc-eth-validator.service','erpc-eth-peer.service','erpc-eth-peer.timer')
CHECKPOINT={'mainnet':'https://mainnet.checkpoint.sigp.io','hoodi':'https://hoodi.checkpoint.sigp.io'}


def process_plan(plan):
    accounts.validate(plan,'validator');value=dict(plan,users={})
    for name,identity in plan['users'].items():
        identity=dict(identity)
        if name=='ev-transport':identity['gid']=plan['groups']['ev-reth'];identity['groups']=[]
        else:identity['groups']=sorted(accounts.expected_groups(plan,name)-{identity['gid']})
        value['users'][name]=identity
    return value


def target(value,network):
    require(network in CHECKPOINT and isinstance(value,dict) and set(value)=={'pair','artifacts','fee_recipient'},
            'closed original validator target required')
    require(isinstance(value['pair'],str) and re.fullmatch(r'reth-v[0-9]+\.[0-9]+\.[0-9]+--lighthouse-v[0-9]+\.[0-9]+\.[0-9]+',value['pair']),
            'qualified stable validator client pair required')
    require(isinstance(value['fee_recipient'],str) and re.fullmatch('0x[a-f0-9]{40}',value['fee_recipient'])
            and value['fee_recipient']!='0x'+'0'*40,'explicit validator fee destination required')
    require(isinstance(value['artifacts'],dict) and set(value['artifacts'])=={'reth','lighthouse'},'both original native images required')
    for item in value['artifacts'].values():
        require(isinstance(item,dict) and set(item)=={'sha256'} and isinstance(item['sha256'],str) and re.fullmatch('[a-f0-9]{64}',item['sha256']),
                'original native image digest required')
    return value


def native_arguments(expected,value):
    value=target(value,expected['network']);pair=namespace.PROFILES['validator']['opt']/value['pair'];network=expected['network']
    reth=[str(pair/'reth'),'--color','never','--log.file.max-files','0','node','--chain',network,'--datadir',str(ROOT/'reth'),'--full',
          '--http','--http.addr','127.0.0.1','--http.port','8545','--http.api','eth,net,web3',
          '--authrpc.addr','127.0.0.1','--authrpc.port','8551','--authrpc.jwtsecret',str(RUN/'reth'/'jwt'),
          '--auth-ipc','--auth-ipc.path',str(RUN/'engine'/'engine.ipc'),'--ipc.permissions','660','--ipcdisable',
          '--metrics','127.0.0.1:9002']
    beacon=[str(pair/'lighthouse'),'--network',network,'--datadir',str(ROOT/'beacon'),'--logfile-max-number','0','bn',
            '--execution-endpoint','https://127.0.0.2:8552','--execution-jwt',str(RUN/'beacon'/'jwt'),
            '--checkpoint-sync-url',CHECKPOINT[network],'--http','--http-address','127.0.0.3','--http-port','5052',
            '--http-enable-tls','--http-tls-cert',str(RUN/'beacon'/'server.crt'),'--http-tls-key',str(RUN/'beacon'/'server.key'),
            '--metrics','--metrics-address','127.0.0.1','--metrics-port','5054','--disable-upnp']
    signer=[str(pair/'lighthouse'),'--network',network,'--logfile-max-number','0','vc','--validators-dir',str(ROOT/'vc'/'validators'),
            '--secrets-dir',str(RUN/'validator'),'--disable-auto-discover','--beacon-nodes','https://127.0.0.3:5052',
            '--beacon-nodes-tls-certs',str(RUN/'trust'/'beacon-ca.pem'),'--suggested-fee-recipient',value['fee_recipient'],
            '--enable-doppelganger-protection','--metrics','--metrics-address','127.0.0.1','--metrics-port','5064']
    return dict(zip((UNITS[0],UNITS[2],UNITS[3]),(reth,beacon,signer)))


def external(revision,action,unit=None):
    require(re.fullmatch('[a-f0-9]{64}',revision) and action in ('guard','engine-serve','peer-observe'),
            'invalid original validator entrypoint')
    profile=namespace.VALIDATOR_FILES;directory=namespace.PROFILES['validator']['helpers']/'releases'/revision
    program=read(namespace.SOURCE/'eth_trust.py').decode()+"\nimport hashlib,os,runpy,sys\n"
    program+='trusted_imports('+repr(str(directory))+')\nprofile='+repr(profile)+'\ndirectory='+repr(str(directory))+'\n'
    program+='if set(os.listdir(directory))!=set(profile):raise ValueError("original validator helper profile differs")\n'
    program+='h=hashlib.sha256()\nfor name in profile:\n with open(os.path.join(directory,name),"rb") as f:\n  for block in iter(lambda:f.read(131072),b""):h.update(block)\n'
    program+='if h.hexdigest()!='+repr(revision)+':raise ValueError("original validator helper digest differs")\n'
    args=[str(directory/'eth_validator_control.py'),action]
    if unit is not None:
        require(unit in UNITS,'unknown original validator service');args.append(unit)
    program+='sys.argv='+repr(args)+'\nrunpy.run_path('+repr(args[0])+",run_name='__main__')\n"
    return '/usr/bin/python3 -I -c '+quoted("exec(bytes.fromhex('"+program.encode().hex()+"'))")


def hardening(writable):
    return ('UMask=0077\nLimitCORE=0\nKillMode=control-group\nSendSIGKILL=no\nKillSignal=SIGINT\n'
            'SuccessExitStatus=130 143 SIGINT SIGTERM\nTimeoutStopSec=600\nLimitNOFILE=1048576\n'
            'UnsetEnvironment=HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy SSLKEYLOGFILE\n'
            'NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nPrivateDevices=yes\n'
            'ProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectKernelLogs=yes\nProtectControlGroups=yes\n'
            'ProtectClock=yes\nRestrictSUIDSGID=yes\nRestrictNamespaces=yes\nRestrictRealtime=yes\nLockPersonality=yes\n'
            'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\nSystemCallArchitectures=native\n'
            'ReadWritePaths='+writable+' /var/lib/erpc-ethereum-authority/validator /run/erpc-eth-validator\n')


def render(expected,value,plan,revision,operation):
    require(expected['role']=='validator' and re.fullmatch('[a-f0-9]{32}',operation),'original validator operation required')
    accounts.validate(plan,'validator');arguments=native_arguments(expected,value);definitions={}
    dependencies={UNITS[0]:'',UNITS[2]:UNITS[0]+' '+UNITS[1],UNITS[3]:UNITS[2]}
    for unit,user,data in [(UNITS[0],'ev-reth','reth'),(UNITS[2],'ev-beacon','beacon'),(UNITS[3],'ev-validator','vc')]:
        identity=plan['users'][user]
        environment=''
        if unit in (UNITS[2],UNITS[3]):
            selected='engine-with-public-ca.pem' if unit==UNITS[2] else 'beacon-ca.pem'
            environment='Environment=SSL_CERT_FILE='+str(RUN/'trust'/selected)+'\nEnvironment=SSL_CERT_DIR='+str(RUN/'trust'/'empty')+'\n'
        definitions[unit]=('[Unit]\nDescription=Original Ethereum validator '+data+'\nAfter=network-online.target '+dependencies[unit]+
            '\nWants=network-online.target '+dependencies[unit]+'\n[Service]\nType=simple\nUser='+str(identity['uid'])+
            '\nGroup='+str(identity['gid'])+'\nExecStartPre=+'+external(revision,'guard',unit)+'\nExecStart='+
            ' '.join(quoted(arg) for arg in arguments[unit])+'\n'+environment+
            ('Restart=no\nTimeoutStartSec=660\n' if unit==UNITS[3] else 'Restart=on-failure\nRestartSec=10\n')+
            'CapabilityBoundingSet=\n'+hardening(str(ROOT/data))+'\n[Install]\nWantedBy=multi-user.target\n')
    definitions[UNITS[1]]=('[Unit]\nDescription=Original validator Engine TLS transport\nAfter='+UNITS[0]+'\nWants='+UNITS[0]+
        '\n[Service]\nType=simple\nUser=root\nGroup=root\nExecStartPre='+external(revision,'guard',UNITS[1])+\
        '\nExecStart='+external(revision,'engine-serve')+'\nRestart=on-failure\nRestartSec=10\nCapabilityBoundingSet=CAP_SETUID CAP_SETGID\n'+
        hardening(str(RUN))+'\n[Install]\nWantedBy=multi-user.target\n')
    definitions[UNITS[4]]=('[Unit]\nDescription=Original validator IPC peer and TLS lifetime observation\n[Service]\nType=oneshot\nUser=root\nGroup=root\nExecStart='+
        external(revision,'peer-observe')+'\nLimitCORE=0\nUMask=0077\nTimeoutStartSec=30\n')
    definitions[UNITS[5]]=('[Unit]\nDescription=Observe original validator peer and credential lifetime\n[Timer]\nOnBootSec=5\nOnUnitActiveSec=20\nAccuracySec=1\nUnit='+
        UNITS[4]+'\n[Install]\nWantedBy=timers.target\n')
    return {'contract':expected,'target':value,'accounts':plan,'revision':revision,'intent':operation,'definitions':definitions,'arguments':arguments}


def interpreter():
    import os
    import stat
    from eth_files import file_digest
    link=Path('/usr/bin/python3');info=link.lstat()
    if stat.S_ISLNK(info.st_mode):
        require(info.st_uid==0 and re.fullmatch(r'python3\.[0-9]{1,2}',os.readlink(link)),'unknown system Python selector')
        path=link.parent/os.readlink(link)
    else:path=link
    namespace.file(path,missing=False)
    return str(path),file_digest(path)


def process_receipt(expected,value,plan,revision,operation):
    import shlex
    receipt=render(expected,value,plan,revision,operation);result={}
    mapping={UNITS[0]:'ev-reth',UNITS[2]:'ev-beacon',UNITS[3]:'ev-validator'}
    for unit,argv in receipt['arguments'].items():
        client='reth' if unit==UNITS[0] else 'lighthouse';identity=plan['users'][mapping[unit]]
        result.setdefault(argv[0],[]).append({'uid':identity['uid'],'gid':identity['gid'],'unit':unit,'argv':argv,
                                            'sha256':value['artifacts'][client]['sha256']})
    image,sha=interpreter();identity=process_plan(plan)['users']['ev-transport']
    result[image]=[{'uid':identity['uid'],'gid':identity['gid'],'unit':UNITS[1],
                    'argv':shlex.split(external(revision,'engine-serve')),'sha256':sha}]
    receipt['processes']=result;return receipt


def retained(state,expected):
    state.check(expected);result=[]
    for path in state.directory.glob('validator-units-*.json'):
        require(len(result)<4096,'original validator unit history exceeds its bound')
        value=state.get(path.name)
        require(value['contract']==expected and set(value['definitions'])==set(UNITS),'original validator unit history differs')
        result.append(value)
    return result


def retained_processes(state,expected):
    approved={}
    for receipt in retained(state,expected):
        for image,entries in receipt['processes'].items():
            for entry in entries:
                if entry not in approved.setdefault(image,[]):approved[image].append(entry)
    return approved


def installed(receipt):
    for name,definition in receipt['definitions'].items():
        require(name in UNITS and read(namespace.SYSTEMD/name)==definition.encode(),'original validator unit bytes differ')


def publish(state,expected,operation,receipt):
    import os
    from eth_files import atomic,synchronize
    current=state.current(expected,operation)
    require(state.get('cutover.json')==current and receipt['contract']==expected and receipt['intent']==operation,
            'original stopped validator unit publication required')
    namespace.paths('validator');name='validator-units-'+operation+'.json'
    if state.exists(name):require(state.get(name)==receipt,'original validator unit publication changed')
    else:state.put(name,receipt)
    synchronize(state.path(name))
    for unit,definition in receipt['definitions'].items():
        state.current(expected,operation);require(unit in UNITS,'unknown original validator unit')
        path=namespace.SYSTEMD/unit
        if path.is_symlink():
            require(path.lstat().st_uid==0 and os.readlink(path)=='/dev/null','unowned validator unit selector')
            path.unlink()
        atomic(path,definition.encode(),0o644)
    installed(receipt)


def owned_action(state,expected,run,action,selected):
    import hashlib
    import os
    require(action in ('stop','disable') and set(selected)<=set(UNITS),'unsupported original validator service action')
    known={name:set() for name in selected}
    for receipt in retained(state,expected):
        for name in selected:known[name].add(hashlib.sha256(receipt['definitions'][name].encode()).hexdigest())
    failures=[]
    for name in selected:
        try:
            path=namespace.SYSTEMD/name
            if path.is_symlink():
                require(path.lstat().st_uid==0 and os.readlink(path)=='/dev/null','unowned validator service mask')
                require(run(['/usr/bin/systemctl','show',name,'--property=MainPID','--value']).strip()==b'0',
                        'masked original validator retains a process');continue
            if not path.exists():
                require(run(['/usr/bin/systemctl','show',name,'--property=LoadState','--value'],allowed=(0,1)).strip()==b'not-found',
                        'missing original validator definition remains loaded')
                if name in UNITS[:4]:require(run(['/usr/bin/systemctl','show',name,'--property=MainPID','--value'],allowed=(0,1)).strip()==b'0',
                                             'missing original validator unit still has a main process')
                continue
            require(hashlib.sha256(read(path)).hexdigest() in known[name],'unowned service cannot acquire original shutdown authority')
            namespace.paths('validator');run(['/usr/bin/systemctl','daemon-reload'])
            run(['/usr/bin/systemctl',action,name],timeout=660)
        except Exception:failures.append(name)
    require(not failures,'original validator service action incomplete; custody and data retained')


def privileged_starters_absent(selected):
    """A missing MainPID/UID match cannot hide a root pre-start or UID-drop phase.

    Never signal an unproved root process. Its presence makes the attempted
    shutdown/cutover fail closed until PID1 has actually drained the unit.
    """
    import os
    import eth_process as processes
    require(set(selected)<=set(UNITS[:4]),'unknown original startup cgroup')
    own=processes.bounded(processes.PROC/'self'/'cgroup',16384).splitlines()
    require(len(own)==1 and own[0].startswith(b'0::/'),'original validator requires the unified Linux cgroup hierarchy')
    groups={('0::/system.slice/'+name+'\n').encode() for name in selected};count=0
    for path in processes.PROC.iterdir():
        if not path.name.isdecimal() or int(path.name)==os.getpid():continue
        count+=1;require(count<=1000000,'startup process namespace exceeds its bound')
        try:
            if processes.bounded(path/'cgroup',16384) not in groups:continue
            _,status=processes.generation(path)
            if status in (b'Z',b'X'):continue
            credentials=processes.credentials(path)
            require(0 not in credentials['Uid'],'original service retains a privileged startup process; restore its owned unit and stop it before retrying')
        except (FileNotFoundError,ProcessLookupError):continue

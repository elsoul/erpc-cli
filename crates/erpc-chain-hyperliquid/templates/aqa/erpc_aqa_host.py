# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original separate-host authority, closed runtime publication and lifecycle."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import shutil
import stat
import time
import types
from erpc_aqa_common import ROOT,CONFIG,HELPERS,RELEASES,UNIT,RUNTIME_FILES,atomic,digest,execute,fsync_dir,json_bytes,owned_directory,read,require,token,unique_json
from erpc_aqa_state import State
from erpc_aqa_trust import trusted_release
import erpc_aqa_accounts as accounts
import erpc_aqa_artifact as artifact
import erpc_aqa_custody as custody
import erpc_aqa_process as process
import erpc_aqa_public as public
import erpc_aqa_units as units

SOURCE=Path(__file__).absolute().parent
SYSTEMD=Path('/etc/systemd/system')
FIREWALL_ROOT=Path('/etc/erpc/hyperliquid-aqa')
FIREWALL=Path('/usr/local/lib/erpc/rpc-firewall.py')
MACHINE=Path('/etc/machine-id')
INTERPRETER=Path('/usr/bin/python3')


def contract(value):
    require(isinstance(value,dict) and set(value)=={'schema','profile','owner','network','host_binding','identity'}
            and type(value['schema'])is int and value['schema']==1 and value['profile']=='hyperliquid-aqa'
            and value['network'] in ('mainnet','testnet'),'invalid original AQA host profile')
    token(value['owner']);require(re.fullmatch('[a-f0-9]{64}',value['host_binding']),'invalid pinned SSH host binding')
    who=value['identity']
    require(isinstance(who,dict) and set(who)=={'validator','consensus_signer','agent_master','agent','agent_public_key','agent_name'},
            'complete original public agent relationship required')
    for name in ('validator','consensus_signer','agent_master','agent'):public.address(who[name])
    require(who['validator']!=who['consensus_signer'] and who['agent'] not in
            (who['validator'],who['consensus_signer'],who['agent_master'])
            and re.fullmatch('04[a-f0-9]{128}',who['agent_public_key'])
            and re.fullmatch('[a-z0-9_-]{1,16}',who['agent_name']),
            'AQA requires distinct original agent authority and an exact approval name')
    return value


def policy(value):
    require(isinstance(value,dict) and set(value)=={'management_allow'}
            and isinstance(value['management_allow'],list) and len(value['management_allow'])<=128,
            'complete bounded management-only policy required')
    entries=[]
    for item in value['management_allow']:
        require(isinstance(item,str) and len(item)<=64,'invalid management address')
        network=ipaddress.ip_network(item,strict=False)
        require(network.prefixlen>0 and str(network)==item,'canonical restricted management network required')
        entries.append(item)
    require(len(set(entries))==len(entries),'duplicate management networks')
    return {'management_allow':entries}


def catalog():return unique_json(read(SOURCE/'catalog.json'))


def helper_digest():return digest(b''.join(read(SOURCE/name) for name in RUNTIME_FILES))


def qualified(request,exact=True):
    c=contract(request.get('contract'));selected=policy(request.get('policy'));target=request.get('target')
    require(isinstance(target,dict) and set(target)=={'id','sha256','signed_at','helper_sha','config_id'}
            and isinstance(target['id'],str) and re.fullmatch(r'aqa-[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}',target['id'])
            and type(target['signed_at'])is int and 0<target['signed_at']<4102444800,
            'complete bounded publisher target required')
    for name in ('sha256','helper_sha','config_id'):
        require(isinstance(target[name],str) and re.fullmatch('[a-f0-9]{64}',target[name]),'invalid publisher target digest')
    require(digest(json_bytes(selected))==target['config_id'],'management policy differs from its authorization')
    current=catalog();pin=current['artifact']
    if exact:require(target['id']=='aqa-'+current['version'] and target['sha256']==pin['sha256']
                     and target['signed_at']==pin['signed_at'] and target['helper_sha']==helper_digest(),
                     'publisher target differs from the carried qualification')
    return c,target,selected,current


def file(path,private=False,missing=True):
    owned_directory(path.parent)
    if not path.exists() and not path.is_symlink():
        require(missing,'original managed file is missing');return
    info=path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
            and not info.st_mode&0o022 and (not private or stat.S_IMODE(info.st_mode)==0o600),
            'managed authority is indirect, writable, shared or foreign')


def tree(path):
    pending=[path];count=0
    while pending:
        directory=pending.pop();owned_directory(directory)
        for item in directory.iterdir():
            count+=1;require(count<=10000,'managed namespace exceeds its bound')
            if item in (HELPERS/'current',HELPERS/'current.pending'):
                info=item.lstat();require(stat.S_ISLNK(info.st_mode) and info.st_uid==0,'unowned helper selector')
                if item.name=='current':trusted_release(str(HELPERS),[list(RUNTIME_FILES)])
                else:
                    target=Path(os.readlink(item))
                    require(target.parent==HELPERS/'releases' and re.fullmatch('[a-f0-9]{64}',target.name),
                            'pending helper selection leaves its immutable namespace')
                    owned_directory(target)
                    require(set(p.name for p in target.iterdir())==set(RUNTIME_FILES)
                            and digest(b''.join(read(target/name) for name in RUNTIME_FILES))==target.name,
                            'pending helper publication is incomplete')
            elif item.is_dir() and not item.is_symlink():pending.append(item)
            else:file(item)


def protected_paths(runtime=True,create=False):
    for path in (ROOT,CONFIG,HELPERS,RELEASES,FIREWALL_ROOT,SYSTEMD):
        if create:owned_directory(path,True,0o700 if path in (ROOT,FIREWALL_ROOT) else 0o755)
        else:
            probe=path
            while not probe.exists() and not probe.is_symlink():probe=probe.parent
            owned_directory(probe)
        if path in (CONFIG,HELPERS,RELEASES):
            for parent in (*path.parents,path):
                if parent.exists():require(parent.lstat().st_mode&0o001,'public publisher runtime path is not traversable')
    if ROOT.exists():
        for path in ROOT.iterdir():file(path,private=True)
    if runtime:
        for path in (CONFIG,HELPERS,RELEASES,FIREWALL_ROOT):
            if path.exists():tree(path)
    for name in (UNIT,units.FIREWALL_UNIT,units.OBSERVER,units.TIMER):
        file(SYSTEMD/name)
        directory=SYSTEMD/(name+'.d')
        if directory.exists() or directory.is_symlink():
            owned_directory(directory)
            for path in directory.iterdir():
                require(path.name in ('50-erpc-firewall-guard.conf','50-erpc-firewall-guard.conf.new'),
                        'unknown AQA service override cannot be adopted')
                file(path)
    if runtime and FIREWALL.parent.exists():file(FIREWALL)


def machine():
    file(MACHINE,missing=False);value=read(MACHINE,64).strip()
    require(re.fullmatch(b'[a-f0-9]{32}',value),'stable host identity unavailable')
    return digest(value)


def owned(c):
    protected_paths(runtime=False)
    state=State(ROOT);record=state.check(c)
    require(record.get('machine')==machine(),'AQA custody belongs to a different original host')
    return state


def hardware():
    require(platform.system()=='Linux' and platform.machine()=='x86_64','publisher requires Linux x86-64')
    require(Path('/sys/fs/cgroup/cgroup.controllers').is_file(),'publisher requires unified cgroup v2')
    # Ubuntu's /etc/os-release may be its root-managed vendor symlink.
    path=Path('/etc/os-release');owned_directory(path.parent)
    if path.is_symlink():
        require(path.lstat().st_uid==0 and path.resolve()==Path('/usr/lib/os-release'),'OS release origin differs')
        path=Path('/usr/lib/os-release')
    file(path,missing=False)
    values=dict(line.split('=',1) for line in read(path,16384).decode().splitlines() if '=' in line)
    require(values.get('ID','').strip('"')=='ubuntu' and values.get('VERSION_ID','').strip('"')=='24.04',
            'publisher requires qualified Ubuntu24.04')
    output=execute(['/usr/bin/systemctl','--version']).stdout.decode().splitlines()
    require(output and re.match(r'^systemd 255(?: |$)',output[0]),'publisher credential delivery requires systemd255')
    require((os.cpu_count() or 0)>=2 and os.sysconf('SC_PHYS_PAGES')*os.sysconf('SC_PAGE_SIZE')>=1500*1024**2,
            'publisher needs the ERPC two-CPU and nominal two-GiB host policy')


def preflight(request):
    c,_,_,_=qualified(request);protected_paths();hardware()
    if (ROOT/'owner.json').exists():owned(c);return {'reserved':True}
    for path in (ROOT,CONFIG,HELPERS,RELEASES,FIREWALL_ROOT):
        require(not path.exists() or not any(path.iterdir()),'unowned AQA artifacts cannot be adopted')
    for path in (Path('/var/lib/erpc-hyperliquid'),Path('/etc/hyperliquid')):
        require(not path.exists() and not path.is_symlink(),'AQA must use a separate host from native consensus or RPC')
    global_config=FIREWALL_ROOT.parent
    if global_config.exists():
        require(all(path==FIREWALL_ROOT for path in global_config.iterdir()),'another managed chain profile occupies this host')
    require(accounts.lookup(accounts.pwd.getpwnam,accounts.NATIVE) is None
            and accounts.lookup(accounts.grp.getgrnam,accounts.NATIVE) is None,
            'unknown publisher service identity cannot be adopted')
    for name in (UNIT,units.FIREWALL_UNIT,units.OBSERVER,units.TIMER):
        require(not (SYSTEMD/name).exists() and not (SYSTEMD/(name+'.d')).exists(),'unowned publisher boot authority exists')
        load=execute(['/usr/bin/systemctl','show',name,'--property=LoadState','--value'],check=False).stdout.strip()
        require(load==b'not-found','publisher unit already exists outside its ownership record')
    return {'reserved':False}


def reserve(request):
    c,_,_,_=qualified(request);existing=preflight(request)['reserved']
    if not existing:
        protected_paths(create=True)
        State(ROOT).put('owner.json',{'contract':c,'machine':machine()})
    state=owned(c)
    for directory in (ROOT,*ROOT.parents):fsync_dir(directory)
    return state


def publish_helpers():
    protected_paths()
    value=helper_digest();release=HELPERS/'releases';owned_directory(release,True,0o755)
    destination=release/value
    if not destination.exists():
        stage=release/('.pending-'+secrets.token_hex(16));stage.mkdir(mode=0o700)
        for name in RUNTIME_FILES:atomic(stage/name,read(SOURCE/name),0o444)
        require(digest(b''.join(read(stage/name) for name in RUNTIME_FILES))==value,'carried runtime publication readback differs')
        os.chmod(stage,0o755);fsync_dir(stage);os.rename(stage,destination);fsync_dir(release)
    require(set(p.name for p in destination.iterdir())==set(RUNTIME_FILES)
            and digest(b''.join(read(destination/name) for name in RUNTIME_FILES))==value,'immutable runtime changed')
    for name in RUNTIME_FILES:custody.synchronize(destination/name)
    pending=HELPERS/'current.pending'
    if pending.exists() or pending.is_symlink():
        require(pending.is_symlink() and Path(os.readlink(pending))==destination,'another runtime publication is incomplete')
    else:pending.symlink_to(destination)
    os.replace(pending,HELPERS/'current');fsync_dir(HELPERS)
    require(Path(trusted_release(str(HELPERS),[list(RUNTIME_FILES)]))==destination,'published runtime selection differs')
    return value


def firewall(action,*values):
    file(FIREWALL,missing=False);raw=read(FIREWALL)
    module=types.ModuleType('erpc_aqa_firewall');module.__file__=str(FIREWALL)
    exec(compile(raw,str(FIREWALL),'exec'),module.__dict__)
    selected=module.Firewall('hyperliquid-aqa')
    if action in ('apply','confirm'):return getattr(selected,action)(*values)
    return selected.dispatch(action,*values)


def original_account(state,verify=False):
    record=state.get('accounts.json');accounts.account_plan(record)
    require(state.get('account-reservation.json')==record,'original AQA numeric identity reservation differs')
    if verify:accounts.accounts(record)
    return record[accounts.NATIVE]


def retained_receipts(state):
    result=[]
    if (ROOT/'installed.json').exists():result.append(state.get('installed.json')['receipt'])
    if (ROOT/'runtime-prepared.json').exists():result.append(state.get('runtime-prepared.json'))
    return result


def approved_processes(state):
    result={}
    for receipt in retained_receipts(state):
        approved=receipt['processes']
        require(isinstance(approved,dict) and len(approved)<=4,'invalid original process authority receipt')
        for name,record in approved.items():
            require(Path(name).is_absolute() and set(record)=={'argv','sha256'}
                    and isinstance(record['argv'],list) and 1<=len(record['argv'])<=10
                    and all(isinstance(arg,str) and len(arg)<=65536 for arg in record['argv'])
                    and re.fullmatch('[a-f0-9]{64}',record['sha256']),'invalid original process invocation')
            candidates=result.setdefault(name,[])
            if record not in candidates:candidates.append(record)
    return result


def unit_stop(state):
    receipts=retained_receipts(state);failures=[]
    for name in (units.TIMER,UNIT):
        path=SYSTEMD/name
        try:
            if path.exists() or path.is_symlink():
                file(path,missing=False)
                require(digest(read(path)) in [value['units'].get(name) for value in receipts],
                        'unknown unit cannot be stopped or disabled')
                execute(['/usr/bin/systemctl','daemon-reload'])
                try:execute(['/usr/bin/systemctl','stop',name],timeout=150)
                except Exception:failures.append(name+' stop')
                try:execute(['/usr/bin/systemctl','disable',name])
                except Exception:failures.append(name+' disable')
            else:
                load=execute(['/usr/bin/systemctl','show',name,'--property=LoadState','--value'],check=False).stdout.strip()
                require(load==b'not-found','missing publisher unit remains loaded')
        except Exception:failures.append(name+' authority')
    require(not failures,'owned publisher unit stop or disabling failed')


def stop_owned(c):
    state=owned(c)
    if not (ROOT/'accounts.json').exists():
        require(not retained_receipts(state),'runtime exists without original account authority')
        return
    identity=original_account(state)
    process.stop(identity,approved_processes(state),lambda:unit_stop(state))


def capacity():
    for path in (ROOT,CONFIG,RELEASES,HELPERS):
        probe=path
        while not probe.exists():probe=probe.parent
        owned_directory(probe)
        require(shutil.disk_usage(probe).free>=1024**3,'publisher filesystem lacks one GiB of operational headroom')


def clock():
    require(execute(['/usr/bin/timedatectl','show','--property=NTPSynchronized','--value']).stdout.strip()==b'yes',
            'publisher requires synchronized host time')


def approval(state,c,bind=False):
    require(not (ROOT/'agent-revoked').exists(),'observed revoked agent cannot be reused; select a fresh dedicated identity')
    result=public.observe(c)
    if (ROOT/'agent-approval.json').exists():
        if state.get('agent-approval.json')!={'contract':c,'approval':result['approval']}:
            raise public.Revoked('original approval metadata was changed or replaced')
    elif bind:
        state.put('agent-approval.json',{'contract':c,'approval':result['approval']})
        custody.synchronize(ROOT/'agent-approval.json')
    else:raise ValueError('initial external agent approval has not been bound')
    require(result['validator_active'],'original validator is not currently active and unjailed')
    return result


def prepare(request):
    c,target,selected,current=qualified(request);state=owned(c);protected_paths();hardware();capacity()
    identity=original_account(state,True)
    state.begin(c,request['intent'],target,lambda:stop_owned(c))
    process.quiescent(identity,approved_processes(state))
    custody.identity(state,c)
    clock();approval(state,c,bind=True)
    artifact.install(current)
    revision=publish_helpers();require(revision==target['helper_sha'],'prepared helper revision differs')
    state.current(c,request['intent'])
    return {'prepared':True,'target':target,'policy':selected}


def public_runtime(c,state,current):
    who=original_account(state,True);credential=custody.identity(state,c)
    return {'contract':c,'account':who,'version':current['version'],
            'binary_sha256':current['artifact']['binary_sha256'],'dotenv_sha256':credential['dotenv_sha256']}


def configure(request):
    c,target,selected,current=qualified(request);state=owned(c);protected_paths()
    operation=state.current(c,request['intent'])
    require(state.get('installing.json')==operation,'publisher preparation was superseded')
    firewall('require-confirmed',request['run'],request['bundle'])
    identity=original_account(state,True);process.quiescent(identity,approved_processes(state))
    binary=artifact.check(current);runtime=public_runtime(c,state,current)
    definitions=units.render(c,identity)
    launcher=shlex.split(units.bootstrap()+' launch '+c['owner'])
    python=INTERPRETER.resolve();file(python,missing=False)
    process_map={str(binary):{'argv':[str(binary)],'sha256':current['artifact']['binary_sha256']},
                 str(python):{'argv':launcher,'sha256':digest(read(python,32*1024*1024))}}
    receipt={'units':{name:digest(text.encode()) for name,text in definitions.items()},
             'processes':process_map,'runtime_sha256':digest(json_bytes(runtime)),
             'firewall':{'run':request['run'],'bundle':request['bundle']},'policy':selected}
    state.put('runtime-prepared.json',receipt);custody.synchronize(ROOT/'runtime-prepared.json')
    atomic(CONFIG/'runtime.json',json_bytes(runtime),0o444)
    for name,text in definitions.items():atomic(SYSTEMD/name,text.encode(),0o644)
    execute(['/usr/bin/systemctl','daemon-reload'])
    state.current(c,request['intent'])
    state.finish(c,request['intent'],receipt)
    return {'configured':True,'vote_eligibility':'not established by agent approval'}


def service(identity):
    raw=execute(['/usr/bin/systemctl','show',UNIT,
                 '--property=LoadState,ActiveState,SubState,MainPID,FragmentPath,DropInPaths,User,Group,NeedDaemonReload']).stdout
    require(len(raw)<=16384,'publisher service metadata exceeds its bound')
    values={}
    for line in raw.decode().splitlines():
        key,separator,value=line.partition('=');require(separator and key not in values,'ambiguous publisher service metadata');values[key]=value
    require(values.get('LoadState')=='loaded' and values.get('FragmentPath')==str(SYSTEMD/UNIT)
            and values.get('DropInPaths') in ('',str(SYSTEMD/(UNIT+'.d/50-erpc-firewall-guard.conf')))
            and values.get('NeedDaemonReload')=='no' and values.get('User')==str(identity['uid'])
            and values.get('Group')==str(identity['gid']) and values.get('MainPID','').isdecimal(),
            'loaded publisher unit does not match its original authority')
    values['MainPID']=int(values['MainPID']);return values


def qualify(c,intent=None,manual=False):
    state=owned(c);protected_paths();installed=state.guard(c,intent,manual)
    identity=original_account(state,True);current=catalog();runtime=public_runtime(c,state,current)
    target=installed['operation']['target']
    require(target['helper_sha']==helper_digest() and target['id']=='aqa-'+current['version']
            and target['sha256']==current['artifact']['sha256'] and target['signed_at']==current['artifact']['signed_at'],
            'running publisher qualification differs from its approved target')
    require(digest(read(CONFIG/'runtime.json'))==installed['receipt']['runtime_sha256']
            and unique_json(read(CONFIG/'runtime.json'))==runtime,'publisher launch profile changed')
    artifact.check(current);custody.identity(state,c)
    for name,checksum in installed['receipt']['units'].items():
        require(name in (UNIT,units.OBSERVER,units.TIMER,units.FIREWALL_UNIT)
                and digest(read(SYSTEMD/name))==checksum,'publisher unit definition changed')
    expected=installed['receipt']['firewall'];firewall('require-confirmed',expected['run'],expected['bundle'])
    clock();capacity();observed=approval(state,c)
    return state,identity,installed,observed


def guard(c,plaintext=False):
    state,identity,_,observed=qualify(c)
    service(identity);process.quiescent(identity,approved_processes(state))
    if plaintext:custody.runtime_bytes(custody.identity(state,c),identity['uid'])
    return observed


def start(c,intent=None):
    state=owned(c);manual=intent is None and (ROOT/'stopped').exists()
    _,identity,installed,_=qualify(c,intent,manual)
    binary=artifact.check(catalog());native={str(binary):installed['receipt']['processes'][str(binary)]}
    if not manual:
        current=service(identity)
        if current['ActiveState']=='active' and current['SubState']=='running' and current['MainPID']>0:
            generation=process.prove(current['MainPID'],identity,native)
            found,unknown=process.scan(identity,approved_processes(state))
            require(generation is not None and not unknown and found=={current['MainPID']:generation},
                    'publisher has additional or unproved original-UID processes')
            if intent is not None:state.consume(c,intent)
            return {'publisher_started':True,'already_running':True,'accepted_vote':None}
    process.quiescent(identity,approved_processes(state))
    if manual:state.manual_ready(c)
    execute(['/usr/bin/systemctl','daemon-reload'])
    execute(['/usr/bin/systemctl','enable',units.FIREWALL_UNIT,UNIT,units.TIMER])
    execute(['/usr/bin/systemctl','start',UNIT,units.TIMER],timeout=210)
    binary=artifact.check(catalog());native={str(binary):installed['receipt']['processes'][str(binary)]}
    deadline=time.monotonic()+30
    while True:
        running=service(identity)
        require(running['ActiveState']=='active' and running['SubState']=='running' and running['MainPID']>0,
                'publisher startup condition or native process did not start')
        try:
            require(process.prove(running['MainPID'],identity,native) is not None,'publisher process ended during startup')
            break
        except Exception:
            if time.monotonic()>=deadline:raise
            time.sleep(0.1)
    if intent is not None:state.consume(c,intent)
    return {'publisher_started':True,'accepted_vote':None,'vote_eligibility':'not established by agent approval'}


def reject_runtime(c,error):
    state=owned(c);revocation_saved=True
    if isinstance(error,public.Revoked):
        try:state.marker('agent-revoked')
        except Exception:revocation_saved=False
    state.cancel(c,False,lambda:stop_owned(c))
    require(revocation_saved,'owned shutdown attempted but agent revocation was not persisted')


def status(c):
    state=owned(c)
    result={'publisher_service_ready':False,'accepted_vote':None,'vote_eligibility':'not established by agent approval',
            'stopped':(ROOT/'stopped').exists(),'retired':(ROOT/'retired').exists(),
            'installing':(ROOT/'installing.json').exists(),'agent_revoked':(ROOT/'agent-revoked').exists()}
    try:
        _,identity,installed,observation=qualify(c)
        service_state=service(identity)
        require(service_state['ActiveState']=='active' and service_state['SubState']=='running' and service_state['MainPID']>0,
                'publisher service is not running')
        binary=artifact.check(catalog());native={str(binary):installed['receipt']['processes'][str(binary)]}
        start_time=process.prove(service_state['MainPID'],identity,native)
        found,unknown=process.scan(identity,approved_processes(state))
        require(start_time is not None and not unknown and found=={service_state['MainPID']:start_time},
                'publisher process authority is incomplete')
        result.update(publisher_service_ready=True,approval=observation['approval'],
                      validator_active=observation['validator_active'],observed_core_time=observation['observed_core_time'])
    except Exception:result['inspection_error']='original publisher, agent approval or host qualification unavailable'
    return result


def observe(c):
    state=owned(c)
    if not (ROOT/'installed.json').exists():return {'observer':'no installed publisher'}
    if any((ROOT/name).exists() for name in ('stopped','retired','installing.json','activation-revoked')):
        stop_owned(c);return {'observer':'startup fenced; owned stop attempted'}
    # A short completed configuration may precede its explicitly requested
    # activation. Never let an old queued observer cancel that new operation.
    try:
        current=state.get('operation.json')
        if current['intent'] is not None:
            running=service(original_account(state,True))
            if running['ActiveState'] in ('inactive','failed') and running['MainPID']==0:
                return {'observer':'deployment awaits its explicit activation'}
        _,identity,installed,observation=qualify(c)
        running=service(identity)
        require(running['ActiveState']=='active' and running['SubState']=='running' and running['MainPID']>0,
                'publisher service is not running')
        binary=artifact.check(catalog())
        require(process.prove(running['MainPID'],identity,{str(binary):installed['receipt']['processes'][str(binary)]}) is not None,
                'publisher process is unavailable')
        return {'observer':'original authority verified','approval':observation['approval'],'accepted_vote':None}
    except Exception as error:
        reject_runtime(c,error)
        raise ValueError('publisher qualification failed; owned shutdown attempted') from None


def launch(owner):
    # Executed under the original numeric service UID, after the privileged
    # condition and guard. The first condition works from / before credentials
    # exist; only this launcher enters the exact credential directory.
    owned_directory(CONFIG);file(CONFIG/'runtime.json',missing=False)
    value=unique_json(read(CONFIG/'runtime.json'));c=contract(value['contract'])
    require(c['owner']==token(owner),'publisher launcher ownership differs')
    identity=value['account']
    require(set(identity)=={'uid','gid'} and 100<=identity['uid']<=999 and identity['uid']==identity['gid']
            and os.getuid()==identity['uid'] and os.geteuid()==identity['uid']
            and os.getgid()==identity['gid'] and set(os.getgroups())<={identity['gid']},
            'publisher launcher is not the original isolated account')
    current=catalog();require(value['version']==current['version'] and value['binary_sha256']==current['artifact']['binary_sha256'],
                              'publisher launch artifact differs')
    custody.runtime_bytes(value,identity['uid'])
    binary=RELEASES/current['version']/'publish_daemon'
    owned_directory(binary.parent);file(binary,missing=False)
    require(digest(read(binary,current['artifact']['binary_size']))==value['binary_sha256'],'publisher image changed before exec')
    os.chdir(custody.DECRYPTED.parent)
    require(Path.cwd()==custody.DECRYPTED.parent,'publisher dotenv working directory differs')
    # dotenvy populates the native publisher's own environment after exec.
    # No secret is supplied in argv, unit Environment= or this inherited map.
    environment={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
    os.execve(binary,[str(binary)],environment)


EVENT_ACTIONS=('initialize','import-agent','authorize','prepare','configure','activate','start','stop','restart',
               'destroy','recover-preparation','observe','firewall-apply','firewall-confirm')


def event(action,ok):
    require(action in EVENT_ACTIONS,'unknown public lifecycle event')
    path=ROOT/'events.json';rows=unique_json(read(path)) if path.exists() else []
    require(isinstance(rows,list) and len(rows)<=512,'invalid bounded lifecycle journal')
    sequence=rows[-1]['sequence']+1 if rows else 1
    rows.append({'sequence':sequence,'time':int(time.time()*1000),'action':action,'ok':bool(ok)})
    atomic(path,json_bytes(rows[-512:]))


def logs(c,lines,follow):
    owned(c);require(type(lines)is int and 0<=lines<=10000 and type(follow)is bool,'invalid journal bounds')
    last=-1
    while True:
        path=ROOT/'events.json';rows=unique_json(read(path)) if path.exists() else []
        require(isinstance(rows,list) and len(rows)<=512,'invalid bounded lifecycle journal')
        for row in (rows[-lines:] if last<0 and lines else rows if last>=0 else []):
            require(isinstance(row,dict) and set(row)=={'sequence','time','action','ok'} and type(row['time'])is int
                    and type(row['sequence'])is int and row['sequence']>0 and row['action'] in EVENT_ACTIONS and type(row['ok'])is bool,
                    'invalid public lifecycle event')
            if row['sequence']>last:print(json.dumps(row,separators=(',',':')),flush=True)
        if rows:last=max(last,rows[-1]['sequence'])
        if not follow:return
        time.sleep(0.5)

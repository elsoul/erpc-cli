#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original Ethereum RPC authority; invoked only by an externally checked loader."""
import fcntl
import contextlib
import hashlib
import json
import io
import os
from pathlib import Path
import re
import sys
sys.dont_write_bytecode=True
from eth_files import ENV,atomic,file_digest,read,require,root_directory,run,synchronize,unique
from eth_state import State,contract,intent
import eth_accounts as accounts
import eth_layout as layout
import eth_namespace as namespace
import eth_process as processes
import eth_units as units
import eth_source_floor as source_floor


def machine():
    raw=read(Path('/etc/machine-id'),128).strip()
    require(re.fullmatch(b'[a-f0-9]{32}',raw),'original host machine identity is unavailable')
    return hashlib.sha256(raw).hexdigest()


def original(state,expected,live_accounts=True):
    require(state.check(expected)['machine']==machine(),'original authority belongs to another machine')
    plan=accounts.validate(state.get('accounts-intent.json'),expected['role'])
    if live_accounts or state.exists('accounts.json'):
        require(state.get('accounts.json')==plan,'original numeric identity receipts differ')
    if live_accounts:accounts.verify(plan)
    return plan


def shutdown(state,expected):
    # NSS drift cannot redirect the original numeric process proof, and must not
    # prevent emergency shutdown of the retained original cgroup/image/PID.
    plan=original(state,expected,False);approved=units.retained_processes(state,expected)
    processes.stop(plan,approved,lambda:units.stop_owned(state,expected,run))


def retire_shutdown(state,expected):
    failed=[]
    try:shutdown(state,expected)
    except Exception:failed.append('owned shutdown')
    try:units.disable_owned(state,expected,run)
    except Exception:failed.append('owned boot disable')
    require(not failed,'original Ethereum retirement incomplete: '+', '.join(failed))


def paused(state,expected):
    if not state.exists('paused.json'):return set()
    value=state.get('paused.json')
    require(set(value)=={'contract','units'} and value['contract']==expected and isinstance(value['units'],list)
            and len(value['units'])==len(set(value['units'])) and set(value['units'])<=set(units.UNITS[:2]),
            'original per-layer startup fence differs')
    return set(value['units'])


def pause(state,expected,names):
    state.check(expected);require(set(names)<=set(units.UNITS[:2]),'unknown original startup scope')
    if state.exists('paused.json'):paused(state,expected)
    state.put('paused.json',{'contract':expected,'units':sorted(names)});synchronize(state.path('paused.json'))


def layer_shutdown(state,expected,names):
    plan=original(state,expected,False);selected={'lighthouse' if name=='lighthouse.service' else 'reth' for name in names}
    scoped=dict(plan,users={name:value for name,value in plan['users'].items() if name in selected})
    approved=units.retained_processes(state,expected)
    processes.stop(scoped,approved,lambda:units.stop_owned(state,expected,run,names))


def needs_reconciliation(state,expected):
    """An already-running original pair is not restarted by an idempotent start."""
    require(not state.halted()['retired'] and not any(state.exists(name) for name in ('pending.json','cutover.json','recovery.json')),
            'start cannot replace retirement or an incomplete original operation')
    active=state.get('active.json');ready(state,expected,active)
    plan=original(state,expected);found,unknown=processes.scan(plan,units.retained_processes(state,expected))
    require(not unknown,'original identities retain an unproved process; explicit owned stop is required')
    run(['/usr/bin/systemctl','daemon-reload']);running={}
    for name,user in [('reth.service','reth'),('lighthouse.service','lighthouse')]:
        raw=run(['/usr/bin/systemctl','show',name,'--property=ActiveState,SubState,MainPID'])
        fields={}
        for line in raw.decode().splitlines():
            key,separator,value=line.partition('=');require(separator and key not in fields,'ambiguous original service state');fields[key]=value
        pid=fields.get('MainPID','');require(pid.isdigit(),'original service PID is unavailable')
        if int(pid)==0:continue
        require(fields.get('ActiveState')=='active' and fields.get('SubState')=='running','original service transition must settle before start')
        try:generation=processes.prove(int(pid),plan['users'][user],active['receipt']['units']['processes'],unit=name)
        except (FileNotFoundError,ProcessLookupError):return True
        require(generation is not None,'original service PID is not a live native writer')
        running[int(pid)]=(generation,plan['users'][user]['uid'])
    return found!=running


def layer_service(state,expected,action,layer):
    require(action in ('start','stop','restart') and layer in ('execution','consensus'),'unknown original layer operation')
    state.check(expected)
    require(not any(state.exists(name) for name in ('pending.json','cutover.json','recovery.json')),
            'partial-layer operations cannot replace a pending deployment; use whole-node stop/recovery')
    stop_names=('lighthouse.service',) if layer=='consensus' else ('lighthouse.service','reth.service','reth-snapshot.service')
    start_names=('reth.service',) if layer=='execution' and action=='start' else ('reth.service','lighthouse.service')
    if action in ('stop','restart'):
        failure=None;desired=None
        try:
            desired=paused(state,expected)|set(stop_names)&set(units.UNITS[:2]);pause(state,expected,desired)
        except Exception:failure='layer cancellation persistence failed'
        try:layer_shutdown(state,expected,stop_names)
        except Exception:failure=(failure+'; ' if failure else '')+'owned layer shutdown failed'
        if failure and desired is not None:
            try:pause(state,expected,desired)
            except Exception:failure+='; durable layer cancellation unavailable'
        require(failure is None,(failure or '')+'; original data retained')
        if action=='stop':return {'stopped':True,'layer':layer,'data_preserved':True}
    # A whole-node cancellation keeps the unrequested layer paused. Starting
    # consensus also starts its execution dependency; execution alone does not.
    halted=state.halted();active=state.get('active.json')
    names=paused(state,expected) if active['generation']==halted['generation'] else set(units.UNITS[:2])
    namespace.paths('rpc');original(state,expected)
    if needs_reconciliation(state,expected):
        layer_shutdown(state,expected,('lighthouse.service',) if start_names==('lighthouse.service',) else
                       ('reth.service','reth-snapshot.service') if start_names==('reth.service',) else stop_names)
    state.start(expected,lambda value:ready(state,expected,value))
    try:
        authorize_opening(state,expected,state.get('active.json'),tuple('lighthouse' if name=='lighthouse.service' else 'reth' for name in start_names))
        pause(state,expected,names-set(start_names))
        run(['/usr/bin/systemctl','start','erpc-eth-firewall.service',*start_names],timeout=660)
        require_running(start_names)
    except Exception:
        state.stop(expected,lambda:shutdown(state,expected));raise
    return {'started':True,'layer':layer}


def firewall(action,receipt=None):
    namespace.paths('rpc')
    source=read(namespace.COMMON_FIREWALL,512*1024)
    scope={'__name__':'erpc_checked_ethereum_firewall','__file__':str(namespace.COMMON_FIREWALL)}
    exec(compile(source,str(namespace.COMMON_FIREWALL),'exec'),scope)
    controller=scope['Firewall']('eth')
    if action in ('require-confirmed','apply','confirm'):
        require(isinstance(receipt,dict) and set(receipt)=={'run','bundle'},'original confirmed firewall receipt required')
        with contextlib.redirect_stdout(io.StringIO()):controller.dispatch(action,receipt['run'],receipt['bundle'])
    else:controller.dispatch(action)


def artifacts(value):
    units.target(value);directory=namespace.PROFILES['rpc']['opt']/value['pair']
    descriptor=root_directory(directory);os.close(descriptor)
    require(set(p.name for p in directory.iterdir())=={'reth','lighthouse'},'qualified pair has unexpected files')
    for client,record in value['artifacts'].items():
        require((directory/client).lstat().st_mode&0o555==0o555,'native binary is not publicly readable and executable')
        require(file_digest(directory/client)==record['sha256'],'original native binary digest differs')


def source_spec(value):
    require(isinstance(value,dict) and set(value)=={'pair','reth_commit','lighthouse_commit','reth_archive','lighthouse_archive',
            'rpc_bind','metrics_bind','checkpoint'},'closed original release request required')
    for key in ('reth_commit','lighthouse_commit','reth_archive','lighthouse_archive'):
        require(isinstance(value[key],str) and re.fullmatch('[a-f0-9]{'+('40' if key.endswith('commit') else '64')+'}',value[key]),
                'qualified source commit/archive digest required')
    units.target({key:value[key] for key in ('pair','rpc_bind','metrics_bind','checkpoint')}|
                 {'artifacts':{'reth':{'sha256':value['reth_archive']},'lighthouse':{'sha256':value['lighthouse_archive']}}})
    return value


def selected_target(state,operation):
    record=state.get('qualified-'+operation['intent']+'.json')
    require(record['source']==operation['target'],'qualified native pair belongs to another source request')
    return units.target(record['target'])


def jwt(state,expected,plan):
    state.check(expected);path=namespace.PROFILES['rpc']['config']/'jwt.hex';record=state.get('engine-jwt.json')
    raw=read(path,128,mode=0o640);info=path.lstat()
    require(re.fullmatch(b'[a-f0-9]{64}\n?',raw) and info.st_gid==plan['groups']['ethereum']
            and record=={'contract':expected,'sha256':hashlib.sha256(raw).hexdigest(),'gid':info.st_gid},
            'original private engine JWT differs')
    synchronize(state.path('engine-jwt.json'))


def initialize_jwt(state,expected,plan):
    state.check(expected);path=namespace.PROFILES['rpc']['config']/'jwt.hex';pending=path.with_name('jwt.pending')
    if state.exists('engine-jwt.json'):
        record=state.get('engine-jwt.json')
        require(record['contract']==expected and record['gid']==plan['groups']['ethereum'],'original engine JWT authority differs')
        synchronize(state.path('engine-jwt.json'))
        if not path.exists():
            require(not path.is_symlink(),'original engine JWT cannot be restored through an indirect entry')
            raw=read(pending,128,mode=0o640)
            require(hashlib.sha256(raw).hexdigest()==record['sha256'],'original pending engine JWT changed')
            synchronize(pending);os.replace(pending,path)
        synchronize(path);jwt(state,expected,plan);return
    require(not path.exists() and not path.is_symlink(),'legacy engine JWT needs explicit original-authority migration')
    wanted={'contract':expected,'gid':plan['groups']['ethereum']}
    if state.exists('engine-jwt-intent.json'):
        require(state.get('engine-jwt-intent.json')==wanted,'engine JWT creation belongs to another original host')
    else:
        require(not pending.exists() and not pending.is_symlink(),'unowned engine JWT staging cannot be adopted')
        state.put('engine-jwt-intent.json',wanted)
    synchronize(state.path('owner.json'));synchronize(state.path('engine-jwt-intent.json'))
    if not pending.exists():
        raw=run(['/usr/bin/openssl','rand','-hex','32'])
        require(re.fullmatch(b'[a-f0-9]{64}\n',raw),'native engine JWT generation failed')
        atomic(pending,raw,0o640,group=plan['groups']['ethereum'])
    raw=read(pending,128,mode=0o640);require(re.fullmatch(b'[a-f0-9]{64}\n',raw),'invalid original staged engine JWT')
    require(pending.lstat().st_gid==plan['groups']['ethereum'],'engine JWT staging group changed')
    synchronize(pending)
    state.put('engine-jwt.json',dict(wanted,sha256=hashlib.sha256(raw).hexdigest()))
    synchronize(state.path('engine-jwt.json'));os.replace(pending,path);synchronize(path)
    jwt(state,expected,plan)


def opening_source(state,expected,active):
    operation=active['intent'];qualified=state.get('qualified-'+operation+'.json')
    require(qualified['target']==active['receipt']['units']['target'],'original opened source differs from active unit authority')
    source_floor.check(state,expected,qualified['source'],qualified['target']['artifacts'])
    return qualified


def authorize_opening(state,expected,active,clients=source_floor.CLIENTS):
    qualified=opening_source(state,expected,active)
    source_floor.authorize(state,expected,original(state,expected),qualified['source'],qualified['target']['artifacts'],clients)


def ready(state,expected,active=None):
    require(state.check(expected)['machine']==machine(),'original authority belongs to another machine')
    active=state.guard(expected) if active is None else active
    namespace.paths('rpc');plan=original(state,expected);layout.verify(state,expected,plan)
    layout.capacity(state,expected,plan)
    opening_source(state,expected,active)
    artifacts(active['receipt']['units']['target']);units.installed(active['receipt']['units']);jwt(state,expected,plan)
    firewall('require-confirmed',active['receipt']['firewall'])
    return active


def reserve(state,expected):
    require(expected['role']=='rpc','RPC authority preparation required');namespace.paths('rpc')
    if not state.exists('owner.json'):
        accounts.allocate('rpc')
        for key in ('config','opt','helpers','firewall'):
            path=namespace.PROFILES['rpc'][key]
            require(not path.exists() or not any(path.iterdir()),'legacy/unowned Ethereum namespace requires explicit original-authority migration')
        for name in units.UNITS:
            for path in (namespace.SYSTEMD/name,namespace.SYSTEMD/(name+'.d')):
                require(not path.exists() and not path.is_symlink(),'unowned Ethereum service cannot be adopted')
        for path in namespace.TUNING:
            require(not path.exists() and not path.is_symlink(),'unowned Ethereum host settings cannot be adopted')
        root=layout.ROOTS['rpc']
        if root.exists() or root.is_symlink():
            descriptor=root_directory(root)
            try:layout.clean_volume(descriptor)
            finally:os.close(descriptor)
    state.reserve(expected,machine())
    if state.exists('accounts.json'):
        plan=original(state,expected)
    else:
        require(not any(state.exists(name) for name in ('layout.json','active.json','engine-jwt.json')),
                'established original identity receipt is missing; restore original authority before host preparation')
        plan=accounts.validate(state.get('accounts-intent.json'),'rpc') if state.exists('accounts-intent.json') else accounts.allocate('rpc')
        accounts.verify(plan,partial=True);accounts.persist(state,plan)
    if state.exists('layout.json'):
        layout.verify(state,expected,plan);synchronize(state.path('layout.json'))
    elif state.exists('layout-intent.json'):
        pending=state.get('layout-intent.json')
        if pending['binding'] is not None:
            descriptor=root_directory(layout.ROOTS['rpc'])
            try:
                layout.volume(state,expected,plan,descriptor)
                require(os.fstat(descriptor).st_ino==pending['binding']['inode'],'original pending data directory changed')
            finally:os.close(descriptor)
        synchronize(state.path('layout-intent.json'))
    return {'reserved':True,'accounts':plan}


def prepare(state,expected):
    reserve(state,expected);plan=accounts.provision(state,'rpc')
    if not state.exists('layout.json'):processes.quiescent(plan,units.retained_processes(state,expected))
    layout.prepare(state,expected,plan);capacity=layout.capacity(state,expected,plan)
    namespace.paths('rpc',create=True);revision=namespace.publish('rpc')
    return {'prepared':True,'accounts':plan,'helper_revision':revision,'capacity':capacity}


def dispatch(state,expected,request):
    require(request.get('contract')==expected,'request belongs to another original Ethereum host')
    action=request.get('action')
    if action=='migrate':
        import eth_migration
        return eth_migration.migrate(state,expected,request['evidence'],machine(),run)
    if action=='reserve':return reserve(state,expected)
    if action=='prepare':return prepare(state,expected)
    require(state.check(expected)['machine']==machine(),'original authority belongs to another machine')
    if action=='public-status':
        plan=original(state,expected,False);current=None
        if state.exists('active.json'):
            current=state.get('active.json')['receipt']['units']['target']['pair']
        valid_jwt=False
        try:jwt(state,expected,plan);valid_jwt=True
        except Exception:pass
        bootstrapped=state.exists('snapshot.json') and state.get('snapshot.json').get('contract')==expected
        return {'current':current,'jwt':valid_jwt,'bootstrapped':bootstrapped,'retired':state.halted()['retired'],
                'paused_layers':sorted(paused(state,expected))}
    if action in ('start','stop','restart') and request.get('layer','both')!='both':
        return layer_service(state,expected,action,request['layer'])
    if action in ('stop','destroy'):
        state.stop(expected,lambda:retire_shutdown(state,expected) if action=='destroy' else shutdown(state,expected),retire=action=='destroy')
        return {'stopped':True,'retired':action=='destroy','data_preserved':True}
    if action=='recover':
        return state.recover(expected,intent(request['intent']),lambda:shutdown(state,expected))
    if action=='upgrade-volume':
        proof=layout.filesystem(request['filesystem']);namespace.paths('rpc')
        if state.exists('migration.json') and not state.exists('migration-complete.json'):
            import eth_migration
            return eth_migration.upgrade_pending_volume(state,expected,proof,machine(),run)
        plan=original(state,expected)
        require(not any(state.exists(name) for name in ('pending.json','cutover.json','recovery.json')),
                'finish original cutover recovery before volume authority upgrade')
        state.stop(expected,lambda:shutdown(state,expected),retire=state.halted()['retired'])
        processes.quiescent(plan,units.retained_processes(state,expected))
        result=layout.upgrade(state,expected,plan,proof)
        result['helper_revision']=namespace.publish('rpc')
        return result
    if action=='deployment':
        original(state,expected,False)
        result={name:state.get(name+'.json') if state.exists(name+'.json') else None
                for name in ('halt','pending','active','cutover','recovery')}
        result['pending_current']=False
        if result['pending'] is not None:
            try:state.current(expected,result['pending']['intent']);result['pending_current']=True
            except Exception:pass
        return result
    namespace.paths('rpc');plan=original(state,expected)
    if action in ('firewall-apply','firewall-confirm','firewall-require'):
        state.current(expected,intent(request['intent']))
        verb={'firewall-apply':'apply','firewall-confirm':'confirm','firewall-require':'require-confirmed'}[action]
        firewall(verb,request['firewall'])
        return {'firewall':verb,'intent':request['intent']}
    if action=='reserve-deploy':
        target=source_spec(request['target']);layout.capacity(state,expected,plan);source_floor.check(state,expected,target)
        operation=state.authorize(expected,intent(request['intent']),target,request['operation'])
        return {'authorized':True,'intent':operation['intent'],'target':target}
    if action=='check-deploy':
        operation=state.current(expected,intent(request['intent']))
        require(operation['target']==source_spec(request['target']),'carried release request differs')
        return {'current':True,'accounts':plan}
    if action=='qualify':
        operation=state.current(expected,intent(request['intent']));spec=source_spec(operation['target'])
        pair=namespace.PROFILES['rpc']['opt']/spec['pair']
        stage=pair.with_name(pair.name+'.pending-'+operation['intent'])
        descriptor=root_directory(stage);os.close(descriptor)
        require(set(path.name for path in stage.iterdir())=={'reth','lighthouse'},'qualified extraction has unexpected members')
        staged={client:file_digest(stage/client) for client in ('reth','lighthouse')}
        if pair.exists() or pair.is_symlink():
            descriptor=root_directory(pair);os.close(descriptor)
            require(all(file_digest(pair/client)==digest for client,digest in staged.items()),'existing pair differs from the signed extraction')
        else:
            state.current(expected,operation['intent']);os.rename(stage,pair)
        for client in staged:synchronize(pair/client)
        target={key:spec[key] for key in ('pair','rpc_bind','metrics_bind','checkpoint')}
        target['artifacts']={client:{'sha256':file_digest(pair/client)} for client in ('reth','lighthouse')}
        artifacts(target)
        record={'source':spec,'target':target};name='release-'+hashlib.sha256(spec['pair'].encode()).hexdigest()+'.json'
        immutable={'pin':{key:spec[key] for key in ('pair','reth_commit','lighthouse_commit','reth_archive','lighthouse_archive')},
                   'artifacts':target['artifacts']}
        if state.exists(name):require(state.get(name)==immutable,'same native version cannot acquire substituted source or image authority')
        else:state.put(name,immutable)
        synchronize(state.path(name));state.current(expected,operation['intent'])
        state.put('qualified-'+operation['intent']+'.json',record);synchronize(state.path('qualified-'+operation['intent']+'.json'))
        return {'qualified':True,'target':target}
    if action=='extract':
        import eth_artifacts
        operation=state.current(expected,intent(request['intent']));source_spec(operation['target'])
        return eth_artifacts.extract(state,expected,operation['intent'],request['archives'])
    if action=='engine-init':
        operation=state.current(expected,intent(request['intent']))
        require(state.get('cutover.json')==operation,'original stopped cutover required for private engine material')
        processes.quiescent(plan,units.retained_processes(state,expected))
        initialize_jwt(state,expected,plan);return {'original_engine_jwt_ready':True}
    if action=='begin':
        layout.capacity(state,expected,plan)
        state.begin(expected,intent(request['intent']),lambda:shutdown(state,expected))
        return {'stopped':True,'intent':request['intent']}
    if action=='install':
        operation=state.current(expected,intent(request['intent']))
        require(state.get('cutover.json')==operation,'original stopped cutover required')
        processes.quiescent(plan,units.retained_processes(state,expected));layout.capacity(state,expected,plan)
        selected=selected_target(state,operation);source_floor.check(state,expected,operation['target'],selected['artifacts']);artifacts(selected);jwt(state,expected,plan);firewall('require-confirmed',request['firewall'])
        revision=namespace.publish('rpc')
        receipt=units.render(expected,selected,plan,revision,operation['intent'])
        units.publish(state,expected,operation['intent'],receipt)
        record={'units':receipt,'firewall':request['firewall']}
        state.put('installed-'+operation['intent']+'.json',record);synchronize(state.path('installed-'+operation['intent']+'.json'))
        run(['/usr/bin/systemctl','daemon-reload'])
        return {'installed':True,'started':False,'intent':operation['intent']}
    if action=='bootstrap':
        operation=state.current(expected,intent(request['intent']))
        require(state.get('cutover.json')==operation,'original stopped cutover required')
        layout.capacity(state,expected,plan);artifacts(selected_target(state,operation))
        units.installed(state.get('installed-'+operation['intent']+'.json')['units'])
        if state.exists('snapshot.json'):
            require(state.get('snapshot.json')['contract']==expected,'snapshot receipt belongs to another original host')
            synchronize(state.path('snapshot.json'));return {'snapshot':'complete'}
        status=run(['/usr/bin/systemctl','show','reth-snapshot.service','--property=ActiveState','--value']).strip()
        if status in (b'active',b'activating'):
            found,unknown=processes.scan(plan,units.retained_processes(state,expected))
            require(not unknown,'snapshot has an unproved original-account process')
            return {'snapshot':'running','observed_processes':len(found)}
        processes.quiescent(plan,units.retained_processes(state,expected))
        state.current(expected,operation['intent'])
        source_floor.authorize(state,expected,plan,operation['target'],selected_target(state,operation)['artifacts'],('reth',))
        run(['/usr/bin/systemctl','reset-failed','reth-snapshot.service'])
        run(['/usr/bin/systemctl','start','--no-block','reth-snapshot.service'])
        return {'snapshot':'submitted'}
    if action=='activate':
        operation=state.current(expected,intent(request['intent']))
        installed=state.get('installed-'+operation['intent']+'.json')
        # Snapshot completion is private root authority; a node-writable marker
        # alone can never bypass the native data bootstrap transition.
        require(state.exists('snapshot.json') and state.get('snapshot.json')['contract']==expected,'original snapshot bootstrap has not completed')
        selected=selected_target(state,operation)
        require(installed['units']['target']==selected,'installed source differs from qualified opening target')
        layout.capacity(state,expected,plan);artifacts(selected);units.installed(installed['units']);jwt(state,expected,plan)
        firewall('require-confirmed',installed['firewall'])
        source_floor.authorize(state,expected,plan,operation['target'],selected['artifacts'])
        state.publish(expected,operation['intent'],installed)
        try:
            ready(state,expected)
            authorize_opening(state,expected,state.get('active.json'))
            pause(state,expected,set())
            run(['/usr/bin/systemctl','enable','--now','erpc-eth-firewall.service','reth.service','lighthouse.service'],timeout=660)
            require_running()
        except Exception:
            state.stop(expected,lambda:shutdown(state,expected));raise
        state.consume(expected,operation['intent']);return {'started':True,'intent':operation['intent']}
    if action in ('start','restart'):
        if action=='restart':state.stop(expected,lambda:shutdown(state,expected))
        # A missing/inactive unit does not authorize a second writer; reconcile
        # the retained original processes before restoring runtime authority.
        if needs_reconciliation(state,expected):shutdown(state,expected)
        active=state.start(expected,lambda value:ready(state,expected,value))
        try:
            authorize_opening(state,expected,state.get('active.json'))
            pause(state,expected,set())
            run(['/usr/bin/systemctl','start','erpc-eth-firewall.service','reth.service','lighthouse.service'],timeout=660)
            require_running()
        except Exception:
            state.stop(expected,lambda:shutdown(state,expected));raise
        return {'started':True,'intent':active['intent']}
    require(False,'unsupported original Ethereum RPC authority operation')


def require_running(selected=('reth.service','lighthouse.service')):
    for name in selected:
        raw=run(['/usr/bin/systemctl','show',name,'--property=ActiveState,SubState,MainPID,Result'])
        fields={}
        for line in raw.decode().splitlines():
            key,separator,value=line.partition('=');require(separator and key not in fields,'ambiguous native startup observation');fields[key]=value
        require(fields.get('ActiveState')=='active' and fields.get('SubState')=='running'
                and fields.get('Result')=='success' and fields.get('MainPID','').isdigit()
                and int(fields['MainPID'])>1,'original Ethereum service did not start')


def boot(action,operation=None):
    state=State('rpc');expected=contract(state.get('owner.json')['contract'])
    if action=='firewall-load':
        original(state,expected,False);firewall('load');return
    if action=='guard':
        require(operation in units.UNITS[:2] and operation not in paused(state,expected),'original layer startup is paused')
        active=ready(state,expected);authorize_opening(state,expected,active,('lighthouse' if operation=='lighthouse.service' else 'reth',));return
    require(action in ('snapshot-guard','snapshot-complete') and operation is not None,'invalid native bootstrap continuation')
    namespace.paths('rpc');plan=original(state,expected);selected=state.current(expected,intent(operation))
    require(state.get('cutover.json')==selected,'snapshot belongs to another original cutover')
    layout.capacity(state,expected,plan);artifacts(selected_target(state,selected));units.installed(state.get('installed-'+operation+'.json')['units'])
    source_floor.authorize(state,expected,plan,selected['target'],selected_target(state,selected)['artifacts'],('reth',))
    if action=='snapshot-complete':
        state.put('snapshot.json',{'contract':expected,'intent':operation,'target':selected['target']})
        synchronize(state.path('snapshot.json'))


def main():
    os.umask(0o077);os.environ.clear();os.environ.update(ENV)
    if len(sys.argv)>1 and sys.argv[1]!='request':
        boot(sys.argv[1],sys.argv[2] if len(sys.argv)>2 else None);return
    raw=sys.stdin.buffer.read(131073);require(len(raw)<=131072,'public authority request exceeds its bound')
    request=unique(raw);expected=contract(request.get('contract'));state=State(expected['role'])
    require(expected['role']=='rpc','validator authority is not installed by the RPC controller')
    # Carried prepare is additionally serialized by the existing node-run lock.
    # Later short requests lock only this original namespace; long snapshot
    # downloads run as separate services, so stop need not wait for the download.
    descriptor=root_directory(state.directory,create=request.get('action') in ('reserve','prepare','migrate'))
    try:
        fcntl.flock(descriptor,fcntl.LOCK_EX)
        result=dispatch(state,expected,request)
    finally:os.close(descriptor)
    print(json.dumps(result,separators=(',',':'),allow_nan=False))


if __name__=='__main__':
    try:main()
    except Exception:
        print('Ethereum original-authority operation refused; private diagnostics withheld',file=sys.stderr);sys.exit(1)

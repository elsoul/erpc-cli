#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original dedicated Ethereum validator controller; private requests use stdin."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import sys
sys.dont_write_bytecode=True
from eth_files import ENV,atomic,digest,encoded,file_digest,read,require,root_directory,run,synchronize,unique
from eth_state import State,contract,intent
import eth_accounts as accounts
import eth_artifacts as archives
import eth_layout as layout
import eth_namespace as namespace
import eth_process as processes
import eth_source_floor as floor
import eth_validator_custody as custody
import eth_validator_engine as engine
import eth_validator_health as health
import eth_validator_history as history
import eth_validator_native as native
import eth_validator_peer as peer
import eth_validator_runtime as runtime
import eth_validator_tls as tls
import eth_validator_units as units

CORE=(units.UNITS[3],units.UNITS[2],units.UNITS[1],units.UNITS[0])


def original(state,expected,live=True):
    require(state.check(expected)['machine']==custody.machine(),'original validator belongs to another machine')
    plan=accounts.validate(state.get('accounts-intent.json'),'validator')
    if live or state.exists('accounts.json'):require(state.get('accounts.json')==plan,'original validator identity receipts differ')
    if live:accounts.verify(plan)
    return plan


def shutdown(state,expected,retire=False):
    plan=original(state,expected,False);failures=[]
    try:units.owned_action(state,expected,run,'stop',(units.UNITS[5],))
    except Exception:failures.append('peer timer')
    try:
        processes.stop(units.process_plan(plan),units.retained_processes(state,expected),
                       lambda:units.owned_action(state,expected,run,'stop',CORE))
    except Exception:failures.append('original native writers')
    try:units.privileged_starters_absent(CORE)
    except Exception:failures.append('privileged original startup process')
    if retire:
        try:units.owned_action(state,expected,run,'disable',CORE+(units.UNITS[5],))
        except Exception:failures.append('original boot disable')
    require(not failures,'validator shutdown incomplete: '+', '.join(failures)+'; original data/custody retained')


def quiescent(state,expected,names=None):
    plan=units.process_plan(original(state,expected,False))
    if names is not None:plan=dict(plan,users={name:value for name,value in plan['users'].items() if name in names})
    mapping={'ev-reth':units.UNITS[0],'ev-transport':units.UNITS[1],'ev-beacon':units.UNITS[2],'ev-validator':units.UNITS[3]}
    units.privileged_starters_absent([mapping[name] for name in plan['users']])
    processes.quiescent(plan,units.retained_processes(state,expected))


def reserve(state,expected):
    require(expected['role']=='validator','dedicated original validator role required');namespace.paths('validator')
    if not state.exists('owner.json'):
        accounts.allocate('validator')
        for key in ('config','opt','helpers'):
            path=namespace.PROFILES['validator'][key]
            require(not path.exists() or not any(path.iterdir()),'existing validator namespace needs explicit original-authority migration')
        for name in units.UNITS+('reth.service','lighthouse.service','reth-snapshot.service'):
            require(run(['/usr/bin/systemctl','show',name,'--property=LoadState','--value'],allowed=(0,1)).strip()==b'not-found'
                    and run(['/usr/bin/systemctl','show',name,'--property=ActiveState','--value'],allowed=(0,1)).strip() in (b'inactive',b'failed'),
                    'unowned Ethereum service remains loaded or active')
            for path in (namespace.SYSTEMD/name,namespace.SYSTEMD/(name+'.d')):
                require(not path.exists() and not path.is_symlink(),'unowned Ethereum service cannot be adopted')
        for path in (Path('/etc/erpc/eth-validator.json'),Path('/etc/erpc/eth-validator-jwt'),Path('/usr/local/lib/erpc/eth-validator-control')):
            require(not path.exists() and not path.is_symlink(),'legacy validator needs explicit original authority migration')
        data=layout.ROOTS['validator']
        if data.exists() or data.is_symlink():
            descriptor=root_directory(data)
            try:layout.clean_volume(descriptor)
            finally:os.close(descriptor)
    state.reserve(expected,custody.machine())
    if state.exists('accounts.json'):plan=original(state,expected)
    else:
        require(not any(state.exists(name) for name in ('layout.json','active.json','runtime.json','engine-original.json','signer-custody.json','signer-import.json')),
                'completed validator identity evidence is missing; restore original authority instead of recreating it')
        plan=accounts.validate(state.get('accounts-intent.json'),'validator') if state.exists('accounts-intent.json') else accounts.allocate('validator')
        accounts.verify(plan,partial=True);accounts.persist(state,plan)
    return {'reserved':True,'accounts':plan}


def prepare(state,expected):
    reserved=reserve(state,expected)
    if not state.exists('accounts.json'):
        # An unmapped live UID is not available merely because NSS has no row.
        processes.quiescent(units.process_plan(reserved['accounts']),{})
    plan=accounts.provision(state,'validator')
    if not state.exists('layout.json'):quiescent(state,expected)
    layout.prepare(state,expected,plan);capacity=layout.capacity(state,expected,plan)
    namespace.paths('validator',create=True);revision=namespace.publish('validator')
    return {'prepared':True,'accounts':plan,'helper_revision':revision,'capacity':capacity}


def source(value):
    require(isinstance(value,dict) and set(value)=={'pair','reth_commit','lighthouse_commit','reth_archive','lighthouse_archive','fee_recipient','renew_transport'}
            and type(value['renew_transport'])is bool,'closed original validator source request required')
    floor.pins(value)
    require(isinstance(value['fee_recipient'],str) and re.fullmatch('0x[a-f0-9]{40}',value['fee_recipient'])
            and value['fee_recipient']!='0x'+'0'*40,'explicit validator fee recipient required')
    return value


def artifacts(expected,target):
    units.target(target,expected['network']);path=namespace.PROFILES['validator']['opt']/target['pair']
    descriptor=root_directory(path);os.close(descriptor)
    require(set(p.name for p in path.iterdir())=={'reth','lighthouse'},'qualified validator pair has unexpected files')
    for client,pin in target['artifacts'].items():
        require((path/client).lstat().st_mode&0o555==0o555 and file_digest(path/client)==pin['sha256'],
                'original validator image changed')


def selected(state,expected,operation):
    record=state.get('qualified-'+operation['intent']+'.json')
    require(record['source']==operation['target'],'original validator source qualification differs')
    floor.check(state,expected,record['source'],record['target']['artifacts']);artifacts(expected,record['target'])
    return record['target']


def qualify(state,expected,operation):
    spec=source(operation['target']);pair=namespace.PROFILES['validator']['opt']/spec['pair']
    stage=pair.with_name(pair.name+'.pending-'+operation['intent']);descriptor=root_directory(stage);os.close(descriptor)
    require(set(path.name for path in stage.iterdir())=={'reth','lighthouse'},'validator extraction contains unknown members')
    hashes={client:file_digest(stage/client) for client in ('reth','lighthouse')}
    if pair.exists() or pair.is_symlink():
        descriptor=root_directory(pair);os.close(descriptor)
        require(all(file_digest(pair/client)==value for client,value in hashes.items()),'existing validator pair differs from signed payload')
    else:state.current(expected,operation['intent']);os.rename(stage,pair)
    for client in hashes:synchronize(pair/client)
    target={'pair':spec['pair'],'fee_recipient':spec['fee_recipient'],'artifacts':{client:{'sha256':sha} for client,sha in hashes.items()}}
    artifacts(expected,target)
    name='release-'+digest(spec['pair'].encode())+'.json'
    immutable={'pin':{key:spec[key] for key in ('pair','reth_commit','lighthouse_commit','reth_archive','lighthouse_archive')},'artifacts':target['artifacts']}
    if state.exists(name):require(state.get(name)==immutable,'same validator version cannot substitute source or image')
    else:state.put(name,immutable)
    synchronize(state.path(name));state.current(expected,operation['intent'])
    state.put('qualified-'+operation['intent']+'.json',{'source':spec,'target':target});synchronize(state.path('qualified-'+operation['intent']+'.json'))
    return {'qualified':True,'target':target}


def active(state,expected,guard=True):
    value=state.guard(expected) if guard else state.get('active.json');original(state,expected)
    target=value['receipt']['units']['target'];artifacts(expected,target);units.installed(value['receipt']['units'])
    qualified=state.get('qualified-'+value['intent']+'.json')
    require(qualified['target']==target,'active validator source differs');floor.check(state,expected,qualified['source'],target['artifacts'])
    return value,qualified


def running(selected):
    for name in selected:
        values={line.split('=',1)[0]:line.split('=',1)[1] for line in run(['/usr/bin/systemctl','show',name,'--property=ActiveState,SubState,MainPID,Result']).decode().splitlines() if '=' in line}
        require(values.get('ActiveState')=='active' and values.get('SubState')=='running' and values.get('Result')=='success'
                and values.get('MainPID','').isdigit() and int(values['MainPID'])>1,'original validator service did not start')



def cancel_and_stop(state,expected,retire=False):
    import eth_validator_keys as keys
    # Host retirement during original legacy conversion requires a fresh deploy;
    # it is not permanent destruction/migration of the consensus identity.
    failures=[]
    try:host_retired=retire or state.halted()['retired']
    except Exception:
        host_retired=True;failures.append('original cancellation readback')
    try:keys.cancel(state,expected,retire)
    except Exception:failures.append('signer permission cancellation')
    try:state.stop(expected,lambda:shutdown(state,expected,True),retire=host_retired)
    except Exception:failures.append('original cancellation/shutdown')
    if failures:
        try:keys.cancel(state,expected,retire)
        except Exception:failures.append('durable signing permission unavailable')
    require(not failures,'original validator cancellation incomplete: '+', '.join(failures)+'; original data and ciphertext retained')


def status(state,expected):
    import eth_validator_keys as keys
    original(state,expected,False);imported=keys.current(state,expected);permission=keys.permission(state,expected)
    result={'network':expected['network'],'state':'prepared' if imported is None else 'imported' if imported['phase']=='complete' else 'importing',
            'pubkey':'' if imported is None else imported['pubkey'],'ready':False,'signer_active':False,'activation':'unknown',
            'signing_enabled':permission['enabled'],'retired':state.halted()['retired'] or permission['retired']}
    if result['retired'] or permission['fenced_to'] is not None:result['state']='fenced'
    try:result['signing_enabled']=permission['enabled'] and permission['generation']==state.guard(expected)['generation']
    except Exception:result['signing_enabled']=False
    result['services']={}
    for name in units.UNITS[:4]:
        try:result['services'][name]=run(['/usr/bin/systemctl','show',name,'--property=ActiveState','--value'],allowed=(0,1)).decode().strip()
        except Exception:result['services'][name]='unknown'
    try:
        value,_=active(state,expected,False);plan=original(state,expected)
        if result['services'].get(units.UNITS[3])=='active':
            pid=run(['/usr/bin/systemctl','show',units.UNITS[3],'--property=MainPID','--value']).strip()
            require(pid.isdigit(),'original signer PID missing')
            result['signer_active']=processes.prove(int(pid),units.process_plan(plan)['users']['ev-validator'],value['receipt']['units']['processes'],unit=units.UNITS[3]) is not None
        result.update(health.readiness(state,expected))
        if imported is not None:
            found=health.validator(state,expected,imported['pubkey']);result['activation']='not_in_beacon_state' if found is None else found['status']
            if found is not None:result['balance_gwei']=found['balance'];result['slashed']=found['validator']['slashed']
    except Exception:result['readiness_error']='original identity, source, TLS, network or sync observation unavailable'
    return result


def start(state,expected,restart=False):
    import eth_validator_keys as keys
    original(state,expected,False)
    require(not any(state.exists(name) for name in ('pending.json','cutover.json','recovery.json')),'finish original deployment/recovery before signing')
    try:
        original(state,expected);namespace.paths('validator')
        permission=keys.permission(state,expected)
        require(not permission['retired'] and permission['fenced_to'] is None,'original signer is permanently retired or migrated')
        if restart:cancel_and_stop(state,expected)
        observed=status(state,expected)
        if observed['signer_active']:
            keys.guard(state,expected);return dict(observed,started=True,already=True)
        quiescent(state,expected,('ev-validator',))
        state.start(expected,lambda value:active(state,expected,False))
        value,qualified=active(state,expected);plan=original(state,expected)
        floor.authorize(state,expected,plan,qualified['source'],qualified['target']['artifacts'])
        run(['/usr/bin/systemctl','enable','--now',*units.UNITS[:3],units.UNITS[5]],timeout=660)
        health.readiness(state,expected)
        imported=keys.current(state,expected);require(imported is not None,'original signer has no completed import')
        keys.export_history(state,expected,plan,namespace.PROFILES['validator']['opt']/qualified['target']['pair']/'lighthouse',
                            lambda:quiescent(state,expected,('ev-validator',)))
        keys.enable(state,expected)
        run(['/usr/bin/systemctl','enable',units.UNITS[3]])
        run(['/usr/bin/systemctl','start','--no-block',units.UNITS[3]])
    except Exception:
        # Once original scope is established, unsafe custody/NSS/health must not
        # leave an already-running original signer ignored by a failed start.
        cancel_and_stop(state,expected);raise
    observed=status(state,expected)
    return dict(observed,started=observed['signer_active'],pending=not observed['signer_active'])


def deployment(state,expected):
    original(state,expected,False)
    value={name:state.get(name+'.json') if state.exists(name+'.json') else None for name in ('halt','pending','active','cutover','recovery')}
    if value['active'] is not None:value['active']={name:value['active'][name] for name in ('intent','generation','target')}
    value['source_floor']={client:[row['pin'] for row in floor.records(state,expected,client)] for client in floor.CLIENTS}
    value['migration']=None
    if state.exists('legacy-migration-complete.json'):
        completed=state.get('legacy-migration-complete.json');require(completed['contract']==expected,'original legacy conversion scope differs')
        value['migration']={'records':completed['records'],'fee_recipient':state.get('legacy-migration.json')['config']['fee_recipient']}
    value['pending_current']=False
    if value['pending'] is not None:
        try:state.current(expected,value['pending']['intent']);value['pending_current']=True
        except Exception:pass
    return value


def dispatch(state,expected,request):
    require(request.get('owner')==expected['owner'],'original validator request owner differs')
    action=request.get('action')
    if action=='migrate-authority':
        import eth_validator_migration as migration
        return migration.migrate(state,expected,request['proof'],namespace.SOURCE.parent/'validator',run)
    if action=='reserve':return reserve(state,expected)
    if action=='prepare':return prepare(state,expected)
    if action=='log-authority':
        require(state.check(expected)['machine']==custody.machine(),'original journal scope belongs to another host')
        return {'original_journal_authorized':True}
    original(state,expected,False)
    if action in ('stop','destroy'):
        cancel_and_stop(state,expected,retire=action=='destroy')
        return {'stopped':True,'retired':state.halted()['retired'],'keys_and_history_preserved':True}
    if action=='recover':return state.recover(expected,intent(request['intent']),lambda:shutdown(state,expected,True))
    if action in ('custody-backup','custody-restore'):
        import eth_validator_keys as keys
        if action=='custody-backup':return keys.encrypted_backup(state,expected)
        return keys.restore_backup(state,expected,request['backup'],lambda:cancel_and_stop(state,expected))
    if action=='deployment':return deployment(state,expected)
    if action=='status':return status(state,expected)
    if action in ('start','restart'):return start(state,expected,action=='restart')
    namespace.paths('validator');plan=original(state,expected)
    if action in ('key-authority','import','fence-export'):
        import eth_validator_keys as keys
        value,qualified=active(state,expected,action!='fence-export')
        binary=namespace.PROFILES['validator']['opt']/qualified['target']['pair']/'lighthouse'
        if action=='key-authority':return keys.public_authority(state,expected,request['pubkey'],request.get('new_key'),request.get('source_owner'))
        floor.authorize(state,expected,plan,qualified['source'],qualified['target']['artifacts'],('lighthouse',))
        if action=='import':return keys.import_key(state,expected,request,binary,lambda:quiescent(state,expected,('ev-validator',)))
        return keys.fence_export(state,expected,request['destination'],binary,lambda:shutdown(state,expected,True))
    if action=='reserve-deploy':
        target=source(request['target']);floor.check(state,expected,target);layout.capacity(state,expected,plan)
        operation=state.authorize(expected,intent(request['intent']),target,request['operation'])
        return {'authorized':True,'intent':operation['intent']}
    if action=='check-deploy':
        operation=state.current(expected,intent(request['intent']));require(operation['target']==source(request['target']),'carried original validator request differs')
        return {'current':True,'accounts':plan}
    if action=='extract':return archives.extract(state,expected,intent(request['intent']),request['archives'])
    if action=='qualify':return qualify(state,expected,state.current(expected,intent(request['intent'])))
    if action=='begin':
        import eth_validator_keys as keys
        layout.capacity(state,expected,plan);failures=[]
        try:keys.cancel(state,expected)
        except Exception:failures.append('signer permission persistence')
        try:state.begin(expected,intent(request['intent']),lambda:shutdown(state,expected))
        except Exception:failures.append('original cutover/shutdown')
        require(not failures,'validator cutover incomplete: '+', '.join(failures))
        return {'stopped':True,'intent':request['intent']}
    if action=='install':
        operation=state.current(expected,intent(request['intent']));require(state.get('cutover.json')==operation,'original validator stopped cutover required')
        quiescent(state,expected);layout.capacity(state,expected,plan);target=selected(state,expected,operation)
        health.synchronized_clock()
        runtime.prepare(state,expected,lambda:quiescent(state,expected));engine.value(state,expected,create=True)
        for purpose in ('engine','beacon'):tls.renew(state,expected,purpose,operation['intent'],force=operation['target']['renew_transport'])
        provision_transport(state,expected)
        import eth_validator_keys as keys
        if state.exists('legacy-signer.json'):
            floor.authorize(state,expected,plan,operation['target'],target['artifacts'],('lighthouse',))
            keys.finish_legacy(state,expected,namespace.PROFILES['validator']['opt']/target['pair']/'lighthouse',lambda:quiescent(state,expected))
        revision=namespace.publish('validator');receipt=units.process_receipt(expected,target,plan,revision,operation['intent'])
        units.publish(state,expected,operation['intent'],receipt);state.put('installed-'+operation['intent']+'.json',{'units':receipt})
        synchronize(state.path('installed-'+operation['intent']+'.json'));run(['/usr/bin/systemctl','daemon-reload'])
        return {'installed':True,'signing_started':False}
    if action=='activate-support':
        operation=state.current(expected,intent(request['intent']));target=selected(state,expected,operation)
        installed=state.get('installed-'+operation['intent']+'.json');require(installed['units']['target']==target,'installed validator target differs')
        units.installed(installed['units']);layout.capacity(state,expected,plan)
        floor.authorize(state,expected,plan,operation['target'],target['artifacts']);state.publish(expected,operation['intent'],installed)
        try:
            run(['/usr/bin/systemctl','enable','--now',units.UNITS[0],units.UNITS[1],units.UNITS[2],units.UNITS[5]],timeout=660)
            running(units.UNITS[:3])
        except Exception:state.stop(expected,lambda:shutdown(state,expected,True));raise
        state.consume(expected,operation['intent']);return {'supporting_clients':'started','signing_started':False}
    require(False,'unsupported original validator operation')



def grant(state,expected,name,raw):
    consumer={'reth/jwt':'ev-reth','beacon/jwt':'ev-beacon','beacon/server.key':'ev-beacon',
              'beacon/server.crt':'ev-beacon','validator/password':'ev-validator',
              'trust/engine-with-public-ca.pem':'ev-beacon','trust/beacon-ca.pem':'ev-validator'}[name]
    runtime.grant(state,expected,name,raw,lambda _:quiescent(state,expected,(consumer,)))


def public_roots():
    public=read(Path('/etc/ssl/certs/ca-certificates.crt'),1024*1024)
    import ssl
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.load_verify_locations(cadata=public.decode('ascii'))
    return public


def empty_cert_directory():
    empty=native.RUN/'trust'/'empty';descriptor=root_directory(empty,True,0o755)
    try:require(not os.listdir(descriptor),'validator CA-directory override is not empty')
    finally:os.close(descriptor)


def beacon_transport(state,expected):
    _,beacon=tls.ready(state,expected,'beacon');engine_ca=tls.certificate_authority(state,expected,'engine')
    grant(state,expected,'beacon/jwt',engine.value(state,expected))
    grant(state,expected,'beacon/server.crt',beacon['certificate'].encode())
    grant(state,expected,'beacon/server.key',beacon['private_key'].encode())
    grant(state,expected,'trust/engine-with-public-ca.pem',public_roots()+b'\n'+engine_ca.encode())
    empty_cert_directory()


def provision_transport(state,expected):
    # Changed leaves/roots must be published while cutover is still closed and
    # the original readers are quiescent, not by a boot guard after publication.
    grant(state,expected,'reth/jwt',engine.value(state,expected))
    beacon_transport(state,expected)
    grant(state,expected,'trust/beacon-ca.pem',tls.certificate_authority(state,expected,'beacon').encode())


def guard(state,expected,unit):
    require(unit in units.UNITS[:4],'unknown original validator startup')
    value,qualified=active(state,expected);plan=original(state,expected)
    namespace.paths('validator');layout.capacity(state,expected,plan)
    selected_user={units.UNITS[0]:'ev-reth',units.UNITS[1]:'ev-transport',units.UNITS[2]:'ev-beacon',units.UNITS[3]:'ev-validator'}[unit]
    quiescent(state,expected,(selected_user,))
    runtime.prepare(state,expected,lambda:quiescent(state,expected))
    clients=('reth',) if unit==units.UNITS[0] else ('lighthouse',) if unit in (units.UNITS[2],units.UNITS[3]) else ()
    if clients:floor.authorize(state,expected,plan,qualified['source'],qualified['target']['artifacts'],clients)
    if unit==units.UNITS[0]:grant(state,expected,'reth/jwt',engine.value(state,expected))
    elif unit==units.UNITS[1]:tls.ready(state,expected,'engine');engine.value(state,expected)
    elif unit==units.UNITS[2]:beacon_transport(state,expected)
    else:
        import eth_validator_keys as keys
        health.wait_ready(state,expected,lambda:keys.guard(state,expected,ready=False))
        keys.export_history(state,expected,plan,namespace.PROFILES['validator']['opt']/qualified['target']['pair']/'lighthouse',
                            lambda:quiescent(state,expected,('ev-validator',)))
        keys.guard(state,expected,ready=False)
        require(state.guard(expected)==value,'validator activation changed before private grant')
        grant(state,expected,'trust/beacon-ca.pem',tls.certificate_authority(state,expected,'beacon').encode())
        material=custody.reveal(state,expected);grant(state,expected,'validator/password',material['password'].encode())
        empty_cert_directory()
        history.authorize(state,expected,plan,'0x'+material['keystore']['pubkey'].lower())
    return value


def engine_server(state,expected):
    import ssl
    import eth_validator_transport as transport
    guard(state,expected,units.UNITS[1]);_,material=tls.ready(state,expected,'engine')
    descriptors=[]
    try:
        for name,value in [('certificate',material['certificate']),('private-key',material['private_key'])]:
            fd=os.memfd_create('erpc-engine-'+name,os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING);descriptors.append(fd)
            raw=value.encode();offset=0
            while offset<len(raw):offset+=os.write(fd,raw[offset:])
            os.fchmod(fd,0o400);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.load_cert_chain('/proc/self/fd/'+str(descriptors[0]),'/proc/self/fd/'+str(descriptors[1]))
    finally:
        for fd in descriptors:os.close(fd)
    key=bytes.fromhex(engine.value(state,expected).decode().strip())
    identity=units.process_plan(original(state,expected))['users']['ev-transport']
    transport.serve(context,key,native.RUN/'engine'/'engine.ipc',native.RUN/'engine-peer.json',digest(encoded(expected)),runtime.boot(),
                    {name:identity[name] for name in ('uid','gid')})


def observe_peer(state,expected):
    # Unit stop/reconfiguration may overlap the timer; it never clears a fence.
    if state.exists('cutover.json') or state.exists('recovery.json'):return {'original_engine_peer':False,'maintenance':True}
    value,_=active(state,expected);plan=original(state,expected)
    for purpose in ('engine','beacon'):tls.certificate_authority(state,expected,purpose)
    if state.exists('signer-import.json'):
        imported=state.get('signer-import.json')
        if imported['phase']=='complete':history.verify_identity(state,expected,plan,imported['pubkey'])
    try:return peer.publish(state,expected,plan,value['receipt']['units']['processes'],run)
    except peer.Unavailable:
        peer.revoke();return {'original_engine_peer':False,'available':False}


def boot(action,unit=None):
    state=State('validator');expected=contract(state.get('owner.json')['contract'])
    original(state,expected,False)
    if action=='guard':guard(state,expected,unit);return
    if action=='engine-serve':engine_server(state,expected);return
    if action=='peer-observe':
        try:observe_peer(state,expected)
        except Exception:
            # No synchronous stop of this observer's own oneshot service. The
            # original numeric writer proof and timer cancellation remain usable.
            cancel_and_stop(state,expected);raise
        return
    require(False,'unsupported original validator boot entrypoint')


def main():
    os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE,(0,0));require(sys.platform=='linux' and os.geteuid()==0,'original validator controller requires Linux root')
    os.environ.clear();os.environ.update(ENV)
    state=State('validator')
    if sys.argv[1:] and sys.argv[1] not in ('request','carried'):
        boot(sys.argv[1],sys.argv[2] if len(sys.argv)>2 else None);return
    require(sys.argv[1:] in ([],['request'],['carried']),'fixed validator request entrypoint required')
    raw=sys.stdin.buffer.read(16*1024*1024+4097);require(len(raw)<=16*1024*1024+4096,'validator request exceeds its bound')
    envelope=unique(raw);require(isinstance(envelope,dict) and set(envelope)=={'contract','request'},'original validator request envelope required')
    expected=contract(envelope['contract']);require(expected['role']=='validator','original validator role required')
    request=envelope['request'];require(isinstance(request,dict),'closed validator request required')
    if request.get('action') in ('migration-check','migrate-authority'):
        import eth_validator_migration as migration
        require(sys.argv[1:]==['carried'] and request.get('owner')==expected['owner'],'legacy migration requires its sealed carried scope')
        migration.evidence(request['proof'],expected);migration.scope(expected,request['proof'])
        if request['action']=='migration-check':
            print(encoded(migration.preflight(state,expected,request['proof'],namespace.SOURCE.parent/'validator',run)).decode());return
    directory=root_directory(state.directory,create=request.get('action') in ('reserve','prepare','migrate-authority'))
    try:
        fcntl.flock(directory,fcntl.LOCK_EX)
        result=dispatch(state,expected,request)
    finally:os.close(directory)
    print(encoded(result).decode())


if __name__=='__main__':
    try:main()
    except Exception:
        print('original validator operation refused; private diagnostics withheld',file=sys.stderr);sys.exit(1)

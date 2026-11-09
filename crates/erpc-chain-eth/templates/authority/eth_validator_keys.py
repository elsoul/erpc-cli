# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Single original signer import/lease, preserving the live slashing database."""
import os
from pathlib import Path
import re
import secrets
import stat
from eth_files import atomic,checked_file,digest,encoded,read,require,root_directory,synchronize,unique
import eth_layout as layout
import eth_validator_custody as custody
import eth_validator_health as health
import eth_validator_history as history
import eth_validator_native as native
import eth_validator_runtime as runtime


def owner(value):
    require(isinstance(value,str) and re.fullmatch('[A-Za-z0-9]{1,80}',value),'original migration owner required');return value


def current(state,expected):
    state.check(expected)
    if not state.exists('signer-import.json'):return None
    value=state.get('signer-import.json')
    require(value['contract']==expected and value['phase'] in ('validating','custody','history','legacy','complete')
            and type(value['ever_authorized'])is bool,'original signer import authority differs')
    synchronize(state.path('signer-import.json'));return value


def permission(state,expected):
    state.check(expected)
    if not state.exists('signer-permission.json'):return {'enabled':False,'fenced_to':None,'retired':False,'generation':None,'operation':None}
    value=state.get('signer-permission.json')
    require(set(value)=={'contract','enabled','fenced_to','retired','generation','operation'} and value['contract']==expected and type(value['enabled'])is bool and type(value['retired'])is bool,
            'original signer permission differs')
    for name in ('generation','operation'):
        require(value[name] is None or (isinstance(value[name],str) and re.fullmatch('[a-f0-9]{32}',value[name])),'invalid original signing generation')
    if value['enabled']:require(value['generation'] is not None and value['operation'] is not None,'missing original signing generation')
    if value['fenced_to'] is not None:owner(value['fenced_to'])
    synchronize(state.path('signer-permission.json'));return value


def public_authority(state,expected,pubkey,new_key=False,source_owner=None):
    custody.authority(state,expected)
    require(isinstance(pubkey,str) and re.fullmatch('0x[a-f0-9]{96}',pubkey),'original public signing key required')
    allowed=permission(state,expected);require(allowed['fenced_to'] is None and not allowed['retired'],'original signer is permanently fenced')
    imported=current(state,expected)
    if imported is not None:require(imported['pubkey']==pubkey,'original owner already reserved a different signer')
    if imported is None or imported['phase']!='complete':
        health.readiness(state,expected)
        if source_owner is None:
            require(new_key is True and health.validator(state,expected,pubkey) is None,
                    'fresh import requires the asserted never-used key absent from original beacon state')
        else:require(owner(source_owner)!=expected['owner'],'managed migration requires another original owner')
    return {'authorized':True,'pubkey':pubkey}


def attempt(state,expected,plan):
    runtime.verify(state,expected);parent=root_directory(native.RUN/'custody')
    try:
        name='attempt-'+secrets.token_hex(16);os.mkdir(name,0o700,dir_fd=parent)
        descriptor=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        identity=plan['users']['ev-validator'];os.fchown(descriptor,identity['uid'],identity['gid']);os.fchmod(descriptor,0o700)
        os.fsync(descriptor);os.fsync(parent)
    finally:os.close(parent)
    return native.RUN/'custody'/name,descriptor


def write_input(directory,name,raw,identity):
    require(name in ('keystore.json','password','history.json'),'unknown private import stage member')
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fchown(stream.fileno(),identity['uid'],identity['gid'])
        os.fchmod(stream.fileno(),0o400);os.fsync(stream.fileno())
    os.fsync(directory)



def cleanup_attempt(path,identity):
    parent=root_directory(native.RUN/'custody')
    require(path.parent==native.RUN/'custody' and re.fullmatch('attempt-[a-f0-9]{32}',path.name),'private stage is outside its original namespace')
    count=[0]
    def remove(directory):
        for name in os.listdir(directory):
            count[0]+=1;require(count[0]<=10000,'private validation stage exceeds its bound')
            info=os.stat(name,dir_fd=directory,follow_symlinks=False)
            require(info.st_dev==os.fstat(parent).st_dev and info.st_uid in (0,identity['uid']) and not info.st_mode&0o077,'private validation stage has foreign access')
            if stat.S_ISDIR(info.st_mode):
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
                try:remove(child)
                finally:os.close(child)
                os.rmdir(name,dir_fd=directory)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'private validation stage has an indirect entry')
                os.unlink(name,dir_fd=directory)
        os.fsync(directory)
    try:
        directory=os.open(path.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        try:
            info=os.fstat(directory);require(info.st_dev==os.fstat(parent).st_dev and info.st_uid==identity['uid'] and stat.S_IMODE(info.st_mode)==0o700,'private stage owner differs')
            remove(directory)
        finally:os.close(directory)
        os.rmdir(path.name,dir_fd=parent);os.fsync(parent)
    finally:os.close(parent)


def account_command(binary,network,data,args):
    return [str(binary),'--network',network,'--datadir',str(data),'--logfile-max-number','0','account','validator']+args


def export_history(state,expected,plan,binary,quiescent):
    imported=current(state,expected);require(imported is not None,'original signer history is unavailable')
    quiescent();history.verify_identity(state,expected,plan,imported['pubkey'])
    path,directory=attempt(state,expected,plan)
    try:
        output=path/'export.json'
        native.worker(account_command(binary,expected['network'],layout.ROOTS['validator']/'vc',
            ['slashing-protection','export',str(output),'--pubkeys',imported['pubkey']]),identity=plan['users']['ev-validator'])
        fd=os.open('export.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
        with os.fdopen(fd,'rb') as stream:
            checked_file(os.fstat(stream.fileno()),owner=plan['users']['ev-validator']['uid'],mode=0o600)
            raw=stream.read(16*1024*1024+1);require(len(raw)<=16*1024*1024,'original slashing export exceeds its bound')
        value=unique(raw);history.observe(state,expected,plan,imported['pubkey'],value)
        return value
    finally:
        os.close(directory);cleanup_attempt(path,plan['users']['ev-validator'])


def import_key(state,expected,request,binary,quiescent):
    plan=custody.authority(state,expected)['accounts'];material=request['material']
    require(isinstance(material,dict) and {'keystore','password','history'}<=set(material)
            and set(material)<={'keystore','password','history','source','destination'},'closed original import material required')
    secret={name:material[name] for name in ('keystore','password')};pubkey,raw=custody.key_material(secret)
    source_owner=request.get('source_owner');public_authority(state,expected,pubkey,request.get('new_key'),source_owner)
    if source_owner is not None:
        require(material.get('source')==source_owner and material.get('destination')==expected['owner'],'managed signer transfer destination differs')
    history_raw=custody.history(material['history'],expected['network'],pubkey,source_owner is None)
    desired={'contract':expected,'pubkey':pubkey,'keystore_sha256':digest(encoded(material['keystore'])),
             'history_sha256':digest(history_raw),'source_owner':source_owner}
    imported=current(state,expected)
    if imported is not None:
        if any(imported[key]!=value for key,value in desired.items()):
            require(imported['phase']=='validating' and imported['ever_authorized'] is False
                    and all(imported[key]==value for key,value in desired.items() if key!='keystore_sha256')
                    and not any(state.exists(name) for name in ('signer-custody-intent.json','signer-custody.json','signer-original.pending','signer-original.cred','signer-history.json')),
                    'interrupted original import input differs after custody was established')
            # A malformed encrypted envelope may be corrected only for the SAME
            # public key/history, before any native validation has sealed custody.
            # No existing native signing database is opened or cleared here.
            quiescent();vc=layout.open_native(state,expected,plan,'vc')
            try:require(not os.listdir(vc),'unsealed import has unexpected original native data')
            finally:os.close(vc)
            imported=dict(imported,**desired);state.put('signer-import.json',imported);synchronize(state.path('signer-import.json'))
        if imported['phase']=='complete':
            record=custody.receipt(state,custody.authority(state,expected));require(record['material_sha256']==digest(raw),'original signer input differs')
            history.verify_identity(state,expected,plan,pubkey)
            return {'state':'imported','pubkey':pubkey,'signing_started':False}
    quiescent();runtime.prepare(state,expected,quiescent)
    if imported is None:
        vc=layout.open_native(state,expected,plan,'vc')
        try:require(not os.listdir(vc),'unowned original validator data cannot be adopted')
        finally:os.close(vc)
        imported=dict(desired,phase='validating',ever_authorized=False)
        state.put('signer-import.json',imported);synchronize(state.path('signer-import.json'))
    require(imported['ever_authorized'] is False,'previously authorized signer cannot repeat initial import')
    path,directory=attempt(state,expected,plan)
    try:
        identity=plan['users']['ev-validator']
        for name,payload in [('keystore.json',encoded(material['keystore'])),('password',material['password'].encode()),('history.json',history_raw)]:
            write_input(directory,name,payload,identity)
        # Password verification is confined to fresh tmpfs. Native LH writes
        # plaintext passwords into its generated definitions, so this scratch
        # datadir is never the persistent signing datadir.
        native.worker(account_command(binary,expected['network'],path/'verification',
            ['import','--keystore',str(path/'keystore.json'),'--reuse-password','--password-file',str(path/'password')]),identity=identity)
        custody.seal(state,expected,secret)
        state.put('signer-history-input.json',material['history']);synchronize(state.path('signer-history-input.json'))
        imported['phase']='history';state.put('signer-import.json',imported);synchronize(state.path('signer-import.json'))
        # Missing established history is never re-created by a native import.
        if state.exists('signer-history.json'):history.verify_identity(state,expected,plan,pubkey)
        native.worker(account_command(binary,expected['network'],layout.ROOTS['validator']/'vc',
            ['slashing-protection','import',str(path/'history.json')]),identity=identity)
        persist_definition(state,expected,plan,pubkey,material['keystore'])
        export=path/'initial-export.json'
        native.worker(account_command(binary,expected['network'],layout.ROOTS['validator']/'vc',
            ['slashing-protection','export',str(export),'--pubkeys',pubkey]),identity=identity)
        fd=os.open(export.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
        with os.fdopen(fd,'rb') as stream:
            checked_file(os.fstat(stream.fileno()),owner=identity['uid'],mode=0o600)
            data=stream.read(16*1024*1024+1);require(len(data)<=16*1024*1024,'initial history export exceeds its bound')
        history.observe(state,expected,plan,pubkey,unique(data),initial=True)
        imported['phase']='complete';state.put('signer-import.json',imported);synchronize(state.path('signer-import.json'))
        return {'state':'imported','pubkey':pubkey,'signing_started':False}
    finally:
        os.close(directory);cleanup_attempt(path,plan['users']['ev-validator'])


def persist_definition(state,expected,plan,pubkey,keystore):
    identity=plan['users']['ev-validator'];vc=layout.open_native(state,expected,plan,'vc')
    try:
        folder=os.open('validators',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=vc)
        try:
            info=os.fstat(folder);require(info.st_uid==identity['uid'] and info.st_gid==identity['gid'] and stat.S_IMODE(info.st_mode)==0o700,
                                         'original validators directory differs')
            def put(name,payload,user,mode):
                temporary='.erpc-'+secrets.token_hex(16)
                descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=folder)
                try:
                    with os.fdopen(descriptor,'wb') as stream:
                        stream.write(payload);stream.flush();os.fchown(stream.fileno(),user['uid'],user['gid']);os.fchmod(stream.fileno(),mode);os.fsync(stream.fileno())
                        try:checked_file(os.stat(name,dir_fd=folder,follow_symlinks=False),owner=user['uid'],mode=mode)
                        except FileNotFoundError:pass
                        os.replace(temporary,name,src_dir_fd=folder,dst_dir_fd=folder);os.fsync(folder)
                finally:
                    try:os.unlink(temporary,dir_fd=folder)
                    except FileNotFoundError:pass
            definition=[{'enabled':True,'voting_public_key':pubkey,'description':keystore.get('description') or '', 'type':'local_keystore',
                'voting_keystore_path':str(layout.ROOTS['validator']/'vc'/'validators'/'original-keystore.json'),
                'voting_keystore_password_path':str(native.RUN/'validator'/'password')}]
            key=encoded(keystore);config=encoded(definition)
            put('original-keystore.json',key,{'uid':0,'gid':0},0o444)
            # Pinned Lighthouse ValidatorDefinitions::open requests read AND
            # write access even when auto-discovery and its management API are
            # disabled. The private root receipt authenticates these bytes.
            put('validator_definitions.yml',config,identity,0o600)
            state.put('signer-definition.json',{'contract':expected,'pubkey':pubkey,'keystore_sha256':digest(key),'definitions_sha256':digest(config)})
            synchronize(state.path('signer-definition.json'))
        finally:os.close(folder)
    finally:os.close(vc)



def cancel(state,expected,retire=False,destination=None):
    previous=permission(state,expected)
    if destination is not None:
        owner(destination);require(destination!=expected['owner'] and previous['fenced_to'] in (None,destination),
                                   'source already fenced to another managed destination')
    value={'contract':expected,'enabled':False,'retired':previous['retired'] or retire or destination is not None,
           'fenced_to':previous['fenced_to'] if destination is None else destination,
           'generation':previous['generation'],'operation':previous['operation']}
    state.put('signer-permission.json',value);synchronize(state.path('signer-permission.json'))


def enable(state,expected):
    previous=permission(state,expected);imported=current(state,expected)
    require(not previous['retired'] and previous['fenced_to'] is None and imported is not None and imported['phase']=='complete',
            'original signer cannot acquire a new live lease')
    active=state.guard(expected)
    value={'contract':expected,'enabled':True,'retired':False,'fenced_to':None,'generation':active['generation'],'operation':secrets.token_hex(16)}
    state.put('signer-permission.json',value);synchronize(state.path('signer-permission.json'))


def fence_export(state,expected,destination,binary,shutdown):
    custody.authority(state,expected);imported=current(state,expected)
    require(imported is not None and imported['phase']=='complete','source has no completed original key import')
    failures=[]
    try:cancel(state,expected,True,destination)
    except Exception:failures.append('source signer fence persistence')
    try:state.stop(expected,shutdown,retire=True)
    except Exception:failures.append('original source shutdown/cancellation')
    require(not failures,'source migration incomplete; '+', '.join(failures))
    plan=custody.authority(state,expected)['accounts']
    value=export_history(state,expected,plan,binary,shutdown)
    material=custody.reveal(state,expected)
    return dict(material,history=value,source=expected['owner'],destination=destination)


def guard(state,expected,ready=True):
    plan=custody.authority(state,expected)['accounts'];imported=current(state,expected);allowed=permission(state,expected)
    require(imported is not None and imported['phase']=='complete' and allowed['enabled'] is True and allowed['fenced_to'] is None and not allowed['retired'],
            'original signer is not explicitly enabled')
    require(allowed['generation']==state.guard(expected)['generation'],'original signer startup was canceled')
    history.verify_identity(state,expected,plan,imported['pubkey'])
    directory=layout.descendant(state,expected,plan,'vc','validators');record=state.get('signer-definition.json')
    try:
        require(record['contract']==expected and record['pubkey']==imported['pubkey'],'original signer definition authority differs')
        for name,key in [('original-keystore.json','keystore_sha256'),('validator_definitions.yml','definitions_sha256')]:
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
            with os.fdopen(fd,'rb') as stream:
                info=os.fstat(stream.fileno())
                selected=plan['users']['ev-validator'] if name=='validator_definitions.yml' else {'uid':0,'gid':0}
                checked_file(info,owner=selected['uid'],mode=0o600 if name=='validator_definitions.yml' else 0o444)
                require(info.st_gid==selected['gid'],'original native definition group differs');raw=stream.read(128*1024+1)
                require(len(raw)<=128*1024 and digest(raw)==record[key],'original signer definitions or keystore changed')
    finally:os.close(directory)
    synchronize(state.path('signer-definition.json'))
    if ready:health.readiness(state,expected)


def encrypted_backup(state,expected):
    import base64
    binding=custody.authority(state,expected);record=custody.receipt(state,binding)
    cipher=custody.cipher_bytes(state,record)
    return {'schema':1,'contract':expected,'pubkey':record['pubkey'],'ciphertext':base64.b64encode(cipher).decode('ascii')}


def restore_backup(state,expected,value,shutdown):
    import base64
    binding=custody.authority(state,expected);record=custody.receipt(state,binding)
    require(isinstance(value,dict) and set(value)=={'schema','contract','pubkey','ciphertext'}
            and type(value['schema'])is int and value['schema']==1 and value['contract']==expected
            and value['pubkey']==record['pubkey'] and isinstance(value['ciphertext'],str)
            and len(value['ciphertext'])<=custody.CIPHER_LIMIT*2,'original encrypted backup belongs to another authority')
    cipher=base64.b64decode(value['ciphertext'],validate=True)
    require(digest(cipher)==record['cipher_sha256'],'backup is not the original signer ciphertext')
    shutdown()
    return custody.restore(state,expected,cipher,shutdown)


def finish_legacy(state,expected,binary,quiescent):
    """Qualified deploy verifies an already migrated signer without reimporting history."""
    imported=current(state,expected)
    if imported is None:return False
    plan=custody.authority(state,expected)['accounts'];pubkey=imported['pubkey']
    if imported['phase']!='legacy':
        if state.exists('legacy-signer.json'):history.verify_identity(state,expected,plan,pubkey)
        return False
    require(state.get('legacy-signer.json')['database']==history.identity(state,expected,plan),
            'original legacy DB disappeared; never rebuild it from initial history')
    quiescent();runtime.prepare(state,expected,quiescent);material=custody.reveal(state,expected)
    require('0x'+material['keystore']['pubkey'].lower()==pubkey,'original legacy signing key differs')
    path,directory=attempt(state,expected,plan)
    try:
        identity=plan['users']['ev-validator']
        write_input(directory,'keystore.json',encoded(material['keystore']),identity)
        write_input(directory,'password',material['password'].encode(),identity)
        native.worker(account_command(binary,expected['network'],path/'verification',
            ['import','--keystore',str(path/'keystore.json'),'--reuse-password','--password-file',str(path/'password')]),identity=identity)
        require(state.get('legacy-signer.json')['database']==history.identity(state,expected,plan),'original legacy history changed during private validation')
        output=path/'legacy-export.json'
        native.worker(account_command(binary,expected['network'],layout.ROOTS['validator']/'vc',
            ['slashing-protection','export',str(output),'--pubkeys',pubkey]),identity=identity)
        fd=os.open(output.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
        with os.fdopen(fd,'rb') as stream:
            checked_file(os.fstat(stream.fileno()),owner=identity['uid'],mode=0o600)
            raw=stream.read(16*1024*1024+1);require(len(raw)<=16*1024*1024,'original legacy history export exceeds its bound')
        history.adopt_legacy(state,expected,plan,pubkey,unique(raw))
        persist_definition(state,expected,plan,pubkey,material['keystore'])
        imported['phase']='complete';state.put('signer-import.json',imported);synchronize(state.path('signer-import.json'))
        return True
    finally:
        os.close(directory);cleanup_attempt(path,plan['users']['ev-validator'])

# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Execute Rust-built public migration bundles through their real entrypoints.

Input: {bundles:[{action,sha256,bytes}],control:<actual RemoteCommand.line()>}.
Readonly host/NSS/PID1/proc/mount observations are inert fixtures; all ownership,
mask/privilege journals, copies, promotions, source-floor and controller routing
run the actual compiled Python. Original observer parsing has its own actual
entrypoint suite. No native program, sudo, account, mount or key tool executes.
"""
import ast
import contextlib
import copy
import grp
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import pwd
import runpy
import shlex
import stat
import sys
import tarfile
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
sys.dont_write_bytecode=True
REPOSITORY=Path(__file__).resolve().parents[3]
EXPECTED=REPOSITORY/'crates/erpc-chain-solana-native/templates'
TESTS=Path(__file__).resolve().parent
ACTIONS=['migration-reserve','migration-retire','migration-copy','migration-promote-data','migration-custody','migration-prepare-cutover','migration-finalize']


def require(value,message):
    if not value:raise ValueError(message)


def extract(entry,directory):
    raw=bytes(entry['bytes']);require(len(raw)<=4*1024*1024 and hashlib.sha256(raw).hexdigest()==entry['sha256'],'bundle digest differs')
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
        members=archive.getmembers();require(len(members)<=128,'bundle file count exceeds bound')
        for item in members:
            name=Path(item.name)
            require(item.isfile() and not name.is_absolute() and '..' not in name.parts and item.size<=1048576,'unsafe fixture archive')
            data=archive.extractfile(item).read();path=directory/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
            path.write_bytes(data);path.chmod(0o600)
            if item.name.startswith('node/') or item.name=='ansible/solana-native/migration.yml':
                require((EXPECTED/item.name).read_bytes()==data,'bundle is not the current compiled source')
    inventory=json.loads((directory/'inventory.yml').read_bytes())
    hosts=inventory['all']['hosts'];require(len(hosts)==1,'single original fixture host required')
    values=next(iter(hosts.values()));request=values['solana_native_request']
    require(request['action']==entry['action'],'action differs from compiled inventory')
    return values


def main():
    packet=json.loads(sys.stdin.buffer.read(16*1024*1024+1));entries=packet['bundles']
    require([entry['action'] for entry in entries]==ACTIONS,'all seven sealed stages required')
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary).resolve();runs=root/'runs';runs.mkdir()
        values=[];paths=[]
        for index,entry in enumerate(entries):
            directory=runs/('r-fixture-'+str(index))/'bundle';directory.mkdir(parents=True)
            values.append(extract(entry,directory));paths.append(directory)
        public={key:value for key,value in values[0]['solana_native_request'].items() if key not in ('action','cutover')}
        require(all({key:value for key,value in row['solana_native_request'].items() if key not in ('action','cutover')}==public for row in values),'original request drift')
        require(public['legacy']['management_user']=='operator','fixture management login must be operator')
        require(public['legacy']['historical']['machine_id_sha256']==hashlib.sha256(b'1'*32).hexdigest(),
                'packet must use SHA256 of the actual inert original machine bytes b1 repeated32')
        # Import production modules only from the verified compiled bundle.
        sys.path.insert(0,str(paths[0]/'node'))
        for path in sorted((paths[0]/'node').glob('native_*.py')):importlib.import_module(path.stem)
        sys.path.insert(0,str(TESTS))
        from migration_retire import Coordinator
        import native_accounts as accounts
        import native_files as files
        import native_helpers as helpers
        import native_host as host
        import native_migration_retire as retirement
        import native_migration_transfer as transfer
        import native_migration_promote as promotion
        import native_runtime_control as control
        import native_runtime_unit as units
        import native_state as state
        import native_source_floor as floor
        import native_migration_custody as capture
        import native_migration_guard as guard
        from custody import RAW,PUBLIC,EXPECTED as VECTOR_PUBLIC
        ownership={};fd_paths={};real_open=os.open;real_fstat=os.fstat;real_stat=os.stat;real_lstat=os.lstat;real_scandir=os.scandir
        actual_uid=os.getuid();actual_gid=os.getgid()
        def metadata(info):
            fields={name:getattr(info,name) for name in dir(info) if name.startswith('st_')}
            fields['st_uid'],fields['st_gid']=ownership.get((info.st_dev,info.st_ino),(0,0))
            # Shared temp ancestors stand in for the protected production root.
            if stat.S_ISDIR(info.st_mode):fields['st_mode']&=~0o022
            return SimpleNamespace(**fields)
        class Entry:
            def __init__(self,value):self.value=value;self.name=value.name;self.path=value.path
            def stat(self,follow_symlinks=True):return metadata(self.value.stat(follow_symlinks=follow_symlinks))
            def __getattr__(self,name):return getattr(self.value,name)
        class Scan:
            def __init__(self,path):self.iterator=real_scandir(path)
            def __iter__(self):return self
            def __next__(self):return Entry(next(self.iterator))
            def __enter__(self):return self
            def __exit__(self,*_):self.iterator.close()
            def close(self):self.iterator.close()
        def opening(path,flags,*args,**kwargs):
            fd=real_open(path,flags,*args,**kwargs)
            selected=Path(path)
            if 'dir_fd' in kwargs:selected=fd_paths[kwargs['dir_fd']]/selected
            fd_paths[fd]=selected;return fd
        def handoff(fd,uid,gid):
            info=real_fstat(fd);ownership[(info.st_dev,info.st_ino)]=(uid,gid)
        def chown(path,uid,gid,**kwargs):
            info=real_lstat(path);ownership[(info.st_dev,info.st_ino)]=(uid,gid)
        global_patches=[patch.object(os,'getuid',lambda:0),patch.object(os,'geteuid',lambda:0),patch.object(os,'getgid',lambda:0),
            patch.object(os,'fstat',lambda fd:metadata(real_fstat(fd))),patch.object(os,'stat',lambda *a,**kw:metadata(real_stat(*a,**kw))),
            patch.object(os,'lstat',lambda *a,**kw:metadata(real_lstat(*a,**kw))),
            patch.object(Path,'lstat',lambda path,*a,**kw:metadata(real_lstat(path,*a,**kw))),
            patch.object(Path,'stat',lambda path,*a,**kw:metadata(real_stat(path,*a,**kw))),patch.object(os,'scandir',Scan),
            patch.object(os,'open',opening),patch.object(os,'fchown',handoff),patch.object(os,'chown',chown)]
        for item in global_patches:item.start()
        model=None
        try:
            class Model(Coordinator):
                def users(self):
                    old=public['legacy']['historical']
                    return [pwd.struct_passwd(('solv','x',old['uid'],old['gid'],'','/home/solv',self.shell)),
                        pwd.struct_passwd(('operator','x',1002,1102,'','/home/operator','/bin/bash')),*getattr(self,'native_users',{}).values()]
                def group_records(self):
                    old=public['legacy']['historical']
                    return [grp.struct_group(('solv','x',old['gid'],[])),grp.struct_group(('sudo','x',27,['solv','operator'] if 27 in self.groups else ['operator'])),
                        grp.struct_group(('operator','x',1102,[])),*getattr(self,'native_groups',{}).values()]
                def quiet(self,uid):
                    old=public['legacy']['historical']['uid']
                    require(not self.writer and (uid!=old or not self.running),'inert original writer remains')
                def command(self,args):
                    result=super().command(args)
                    if args[:2]==['/usr/sbin/usermod','--groups']:self.groups=[public['legacy']['historical']['gid']]
                    if args[:2]==['/usr/sbin/sshd','-T']:
                        result.stdout=result.stdout.replace(b'port 2222\n',('port '+str(public['ssh_port'])+'\n').encode())
                    return result
                def service(self,args):
                    if args[0]=='/usr/bin/du':return '4096\t'+args[-1]+'\n'
                    return super().service(args)
            model=Model('runTest');model.setUp()
            def trusted(path,create=False,mode=0o755):
                require(any(path==base or base in path.parents for base in (root,model.root)),'fixture path escaped its owned roots')
                if create:path.mkdir(parents=True,exist_ok=True,mode=mode)
                info=path.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,'untrusted fixture root')
            for module in (retirement,retirement.fencing,retirement.privileges):model.patch(module,'root_directory',trusted)
            model.request=copy.deepcopy(values[0]['solana_native_request']);model.contract=public['contract']
            model.groups=[public['legacy']['historical']['gid'],27];model.native_users={};model.native_groups={}
            def lookup(values,key,field):
                for value in values:
                    if getattr(value,field)==key:return value
                raise KeyError(key)
            model.patch(pwd,'getpwnam',lambda name:lookup(model.users(),name,'pw_name'))
            model.patch(pwd,'getpwuid',lambda uid:lookup(model.users(),uid,'pw_uid'))
            model.patch(grp,'getgrnam',lambda name:lookup(model.group_records(),name,'gr_name'))
            model.patch(grp,'getgrgid',lambda gid:lookup(model.group_records(),gid,'gr_gid'))
            model.native.update(image_sha256=public['legacy']['artifact_evidence']['executable_sha256'],
                                image_bytes=public['legacy']['artifact_evidence']['executable_bytes'])
            model.observed['service']['process']=model.native
            model.patch(os,'getgrouplist',lambda name,gid:model.groups if name=='solv' else [gid])
            # Actual source/payload files, with virtual mounted-device observations.
            source_paths={};target_paths={};target_records={};storage={}
            for index,kind in enumerate(('accounts','ledger','snapshots'),1):
                source=model.root/'mnt'/('snapshot' if kind=='snapshots' else kind);source.mkdir(parents=True,mode=0o700)
                data=source/'retained.bin';data.write_bytes(('inert original '+kind+' data\n').encode());data.chmod(0o600)
                for path in (source,data):
                    info=real_lstat(path);ownership[(info.st_dev,info.st_ino)]=(public['legacy']['historical']['uid'],public['legacy']['historical']['gid'])
                target=model.root/'mnt'/('erpc-solana-'+kind);target.mkdir(mode=0o700)
                source_paths[kind]=source;target_paths[kind]=target
                storage[kind]={'uuid':'90000000-0000-0000-0000-00000000000'+str(index),'inode':source.stat().st_ino,'device':[8,index],
                    'mount_id':str(index),'fs':'ext4','uid':public['legacy']['historical']['uid'],'gid':public['legacy']['historical']['gid']}
                target_records[kind]={'uuid':public['contract']['volumes'][kind],'inode':target.stat().st_ino,'fs':'ext4'}
            model.storage=storage;model.observed['storage']=copy.deepcopy(storage)
            model.observed['copy_preflight']={'targets':target_records}
            model.patch(transfer,'PARENT',model.root/'mnt');model.patch(transfer.mounts,'MOUNTS',target_paths)
            model.patch(transfer.mounts,'inspect_volumes',lambda _: {kind:dict(value,total_bytes=2_000_000_000_000,free_bytes=1_000_000_000_000) for kind,value in target_records.items()})
            model.patch(transfer.shutil,'disk_usage',lambda _:SimpleNamespace(total=2_000_000_000_000,free=1_000_000_000_000))
            home=model.root/'var/lib/erpc-solana';home.parent.mkdir(parents=True)
            model.patch(host,'HOME',home);model.patch(host,'STATE',home/'state');model.patch(control,'STATE',home/'state')
            model.patch(accounts,'TRUST_ANCHOR',model.root)
            specs={role:(name,str(model.root/'var/lib'/name)) for role,(name,_) in accounts.SPECS.items()}
            model.patch(accounts,'SPECS',specs);model.patch(floor.units,'MOUNTS',target_paths)
            model.patch(helpers,'RELEASES',model.root/'usr/local/lib/erpc/solana-native/releases')
            model.patch(retirement,'RUNS',runs)
            operation_root=model.root/'opt/erpc';operation_root.mkdir(parents=True);lock=model.root/'native.lock'
            model.patch(control,'OPERATION_ROOT',operation_root);model.patch(control,'LOCK',lock)
            require(public['legacy']['host_identity']['public']==VECTOR_PUBLIC,'public fixture identity differs')
            model.patch(capture.keys,'qualified_material',lambda original:(copy.deepcopy(original['host_identity']),bytearray(json.loads(RAW))))
            model.patch(capture.keys,'classify',lambda *a,**kw:{'bls_authority_checked':True,'commission':None if public['legacy']['role']=='rpc' else 5})
            model.patch(capture.custody,'CUSTODY',home/'custody')
            model.patch(capture.custody,'public',lambda seed:PUBLIC)
            model.patch(capture.custody,'crypt',lambda action,raw:b'inert:'+raw if action=='encrypt' else raw.removeprefix(b'inert:'))
            model.patch(guard,'verify',lambda operation:{'revision':helpers.revision(helpers.contents(helpers.SOURCE))})
            real_runpy=runpy.run_path
            def entry(path,run_name=None,**kwargs):
                # Relocate only the host namespace and root/OS facts. The exact
                # bundled main(), production exception handler and dispatch run.
                values=real_runpy(path,run_name='inert_loaded',**kwargs)
                function=values['main'];namespace=function.__globals__
                namespace.update(STATE=home/'state',OPERATION_ROOT=operation_root,LOCK=lock,__name__='__main__')
                tree=ast.parse(Path(path).read_bytes());require(isinstance(tree.body[-1],ast.If),'production main wrapper missing')
                exec(compile(ast.Module(body=[tree.body[-1]],type_ignores=[]),str(path),'exec'),namespace)
                return values
            model.patch(runpy,'run_path',entry)
            def external(args,**kwargs):
                if args==['/usr/bin/systemctl','reload','ssh.service']:return model.command(args)
                if args[0]=='/usr/bin/systemctl' or args[0]=='/usr/bin/du':
                    return SimpleNamespace(returncode=0,stdout=model.service(args).encode(),stderr=b'')
                if args[0] in ('/usr/sbin/groupadd','/usr/sbin/useradd'):
                    name=args[-1]
                    if args[0].endswith('groupadd'):
                        model.native_groups[name]=grp.struct_group((name,'x',int(args[args.index('--gid')+1]),[]))
                    else:
                        model.native_users[name]=pwd.struct_passwd((name,'x',int(args[args.index('--uid')+1]),int(args[args.index('--gid')+1]),'',
                            args[args.index('--home-dir')+1],args[args.index('--shell')+1]))
                    return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
                return model.command(args)
            import subprocess
            model.patch(subprocess,'run',external)
            model.patch(sys,'platform','linux')
            original_bytes={kind:(path/'retained.bin').read_bytes() for kind,path in source_paths.items()}
            results=[]
            def invoke(program,args,request,source,rejected=False):
                retirement.SOURCE=source;helpers.SOURCE=source
                class Output(io.StringIO):
                    @property
                    def buffer(self):return self
                    def write(self,value):return super().write(value.decode() if isinstance(value,bytes) else value)
                output=Output();error_output=io.StringIO();original_input=sys.stdin;errors=[];failure_seen=False
                def trace(frame,event,arg):
                    if event=='exception' and 'native_' in frame.f_code.co_filename:
                        errors.append((Path(frame.f_code.co_filename).name,frame.f_lineno,type(arg[1]).__name__,str(arg[1])[:180]))
                    return trace
                try:
                    sys.stdin=io.TextIOWrapper(io.BytesIO(json.dumps(request).encode()),encoding='utf-8')
                    sys.argv=['-c',*args]
                    sys.settrace(trace)
                    try:
                        with contextlib.redirect_stdout(output),contextlib.redirect_stderr(error_output):exec(program,{'__name__':'inert_bootstrap'})
                    except (SystemExit,ValueError) as failure:
                        if not rejected:raise AssertionError('actual fixture entry refused: '+repr(errors[:6]+errors[-6:])) from failure
                        failure_seen=True
                finally:sys.stdin=original_input;sys.settrace(None)
                if rejected:
                    require(failure_seen and not output.getvalue(),'invalid original scope executed successfully or emitted a result')
                    return {'refused':True}
                require(not error_output.getvalue(),'actual fixture entry emitted an unexpected diagnostic')
                return json.loads(output.getvalue())
            for index,(entry_data,row,bundle) in enumerate(zip(entries,values,paths)):
                seal=bundle.parent/'sealed.json';seal.write_text(json.dumps({'bundle':entry_data['sha256'],'login':1002,'group':1102}));seal.chmod(0o600)
                request=row['solana_native_request']
                result=invoke(row['solana_native_loader'],[str(bundle/'node/native_runtime_control.py'),'play'],request,bundle/'node')
                results.append({'action':request['action'],'result':result})
                revision=helpers.revision(helpers.contents(bundle/'node'));installed=helpers.RELEASES/revision
                command=shlex.split(packet['control']);require(command[:5]==['sudo','-n','/usr/bin/python3','-I','-c'] and command[-1]=='control','unexpected compiled direct entrypoint')
                old='/usr/local/lib/erpc/solana-native/releases/'+revision
                require(command[5].count(old)==2,'compiled direct helper revision differs')
                program=command[5].replace(old,str(installed))
                os.environ['SUDO_USER']='operator';os.environ['SUDO_UID']='1002'
                status=invoke(program,['control'],dict(public,action='migration-status'),installed)
                require(status['ready'] is None and not status['runtime_inspected'],'progress claimed health')
                if request['action']=='migration-retire':
                    confirm=invoke(program,['control'],dict(public,action='migration-confirm-manager'),installed)
                    require(confirm['manager_reauthenticated'] and not confirm['copy_authorized'],'direct confirmation differs')
                if request['action']=='migration-copy':require(status['copy_recorded_complete'],'copy did not reach its original receipt')
                if request['action']=='migration-custody':
                    private=shlex.split(packet['export']);require(private[-1]=='migration-export','wrong compiled private entry')
                    private_program=private[5].replace(old,str(installed))
                    original_key=invoke(private_program,['migration-export'],dict(public,action='migration-export'),installed)
                    require(original_key==json.loads(RAW),'private original export differs from public vector')
                if request['action']=='migration-finalize':
                    require(status['migration_complete'] and status['cutover']['provider_version']==3,'final native acknowledgment missing')
                    require(state.State(home/'state').get('helper-revision.json')=={'revision':revision},'ordinary native CLI helper is not published')
                    invoke(private_program,['migration-export'],dict(public,action='migration-export'),installed,rejected=True)
                if request['action']=='migration-promote-data':
                    require(status['recorded_phase']=='promoting' and status['data_recorded_promoted'] and not status['migration_complete'],'pending data promotion differs')
            def snapshot():
                return {str(path.relative_to(model.root)):path.read_bytes() for path in model.root.rglob('*')
                        if path.is_file() and not path.is_symlink()}
            before=snapshot();calls=len(model.commands)
            wrong=copy.deepcopy(public);wrong['action']='migration-status';wrong['contract']['name']='another'
            invoke(program,['control'],wrong,installed,rejected=True)
            os.environ['SUDO_USER']='solv';os.environ['SUDO_UID']=str(public['legacy']['historical']['uid'])
            invoke(program,['control'],dict(public,action='migration-status'),installed,rejected=True)
            os.environ['SUDO_USER']='operator';os.environ['SUDO_UID']='1002'
            invoke(program,['control'],dict(public,action='migration-status',key_file='inert concealed decoy'),installed,rejected=True)
            require(snapshot()==before and len(model.commands)==calls,'rejected controller scope mutated original state or called a service')
            for kind,path in source_paths.items():
                require((path/'retained.bin').read_bytes()==original_bytes[kind],'original source bytes changed')
                require((target_paths[kind]/'data/retained.bin').read_bytes()==original_bytes[kind],'promoted copy differs')
            print(json.dumps({'actual_carried_stages':len(results),'manager_reauthenticated':True,'original_data_retained':True,
                'data_recorded_promoted':True,'migration_complete':True,'runtime_started':False,'rejected_scope_cases':3},separators=(',',':')))
        finally:
            if model is not None:model.doCleanups()
            for item in reversed(global_patches):item.stop()

if __name__=='__main__':main()

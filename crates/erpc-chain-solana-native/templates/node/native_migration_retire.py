# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original Solv retirement coordinator, before any native data adoption.

The initial sealed run is uploaded by a separate management identity. After
retirement a fresh direct SSH request by that same identity is required. Public
qualification is retained before the original service is masked; retries never
replace that evidence with whichever account, process or volume is now present.
"""
import hashlib
import os
from pathlib import Path
import pwd
import re
import stat
from native_files import atomic, encoded, json_value, read, require, root_directory, sync_directory, sync_file
from native_contract import validate
from native_state import token
import native_migration_inspect as legacy
import native_migration_fence as fencing
import native_migration_privileges as privileges
import native_process as process
import native_host as host
import native_helpers as helpers
import native_migration_settings as settings
import native_migration_key as keys
import native_migration_bls as bls

STORE=Path('/var/lib/erpc-solana-migration')
SOURCE=Path(__file__).absolute().parent
RUNS=Path('/opt/erpc/runs')
ROOT_UID=0


def scope(request):
    fields={'action','intent','legacy','contract','ssh_port'}
    extended=request.get('action') in ('migration-prepare-cutover','migration-finalize') if isinstance(request,dict) else False
    require(isinstance(request,dict) and set(request)==(fields|{'cutover'} if extended else fields),'invalid original migration request')
    require(request['action'] in ('migration-reserve','migration-retire','migration-confirm-manager','migration-status','migration-copy','migration-promote-data','migration-custody','migration-export','migration-prepare-cutover','migration-finalize'),
            'unsupported original migration operation')
    token(request['intent']);contract=validate(request['contract']);original=request['legacy'];legacy.validate(original)
    require(original.get('host_identity',{}).get('public') != contract.get('authority_account'),
            'recorded withdrawal authority cannot be exported')
    require('artifact_evidence' in original and 'target_volumes' in original and 'settings_sha256' in original and 'host_identity' in original and 'keygen_evidence' in original and 'commission' in original
            and original['network']==contract['network'] and original['target_volumes']==contract['volumes']
            and original['identity_account']==contract['identity_account'] and original['vote_account']==contract['vote_account']
            and (original['role']=='rpc')==(contract['profile']=='agave-native-rpc')
            and type(request['ssh_port'])is int and 1<=request['ssh_port']<=65535,
            'migration native target differs from its original public source')
    catalog=json_value(read(SOURCE/'catalog.json',65536,ROOT_UID))['networks'][original['network']]
    bls.qualified_source(original['network'],original['artifact_evidence']['source'])
    bls.evidence(original)
    import native_source_floor
    native_source_floor.compatible({key:catalog[key] for key in native_source_floor.FULL}, original['source_history']['highest'])
    return {key:value for key,value in request.items() if key not in ('action','cutover')}


def management(original,carried):
    manager=pwd.getpwnam(original['management_user'])
    require(manager.pw_uid not in (0,original['historical']['uid']) and pwd.getpwuid(manager.pw_uid)==manager,
            'original separate management identity differs')
    if carried:
        directory=Path(os.path.abspath(SOURCE)).parent
        run=directory.parent
        require(directory.name=='bundle' and run.parent==RUNS and re.fullmatch('r-[a-z0-9-]{1,62}',run.name),
                'migration requires an original sealed operation bundle')
        root_directory(directory)
        sealed=json_value(read(run/'sealed.json',65536,ROOT_UID))
        require(isinstance(sealed,dict) and set(sealed)=={'bundle','login','group'}
                and isinstance(sealed['bundle'],str) and re.fullmatch('[a-f0-9]{64}',sealed['bundle'])
                and type(sealed['login'])is int and sealed['login']==manager.pw_uid
                and type(sealed['group'])is int and sealed['group']==manager.pw_gid,
                'sealed run was not uploaded by the original separate manager')
    else:
        require(os.environ.get('SUDO_USER')==manager.pw_name and os.environ.get('SUDO_UID')==str(manager.pw_uid),
                'migration confirmation requires a fresh separate management SSH connection')
    return manager.pw_uid


def scheduling(uid,run):
    # A mask does not retire independent user sessions, cron/at work or a second
    # service using the original UID. Unknown launch paths stay unsupported.
    for name in ('var/lib/systemd/linger/solv','var/spool/cron/crontabs/solv','home/solv/.config/systemd/user'):
        path=legacy.ROOT/name
        require(not path.exists() and not path.is_symlink(),'original account has an unqualified scheduled launch path')
    directory=legacy.ROOT/'var/spool/cron/atjobs'
    if directory.exists() or directory.is_symlink():
        root_directory(directory)
        entries=list(directory.iterdir());require(len(entries)<=4096,'queued job namespace exceeds its bound')
        require(all(entry.lstat().st_uid!=uid for entry in entries),'original account has pending queued jobs')
    raw=run(['/usr/bin/systemctl','list-units','--all','--type=service','--plain','--no-legend','--no-pager'])
    names=[]
    for row in raw.splitlines():
        fields=row.split();require(len(fields)>=4 and re.fullmatch('[A-Za-z0-9@_.:\\x2d-]+\\.service',fields[0]),
                                   'loaded service namespace is ambiguous')
        names.append(fields[0])
    require(len(names)<=4096 and len(set(names))==len(names),'loaded service namespace exceeds its bound')
    for name in names:
        if name=='solv.service':continue
        value=run(['/usr/bin/systemctl','show',name,'--property=User','--value']).strip()
        require(value not in ('solv',str(uid)) and name!='user@'+str(uid)+'.service',
                'another service retains original account execution authority')


def original_processes(uid,main_pid):
    """Do not signal unidentified processes; only the qualified unit may stop."""
    seen=0
    for directory in process.PROC.iterdir():
        if not directory.name.isdecimal():continue
        seen+=1;require(seen<=1_000_000 and not directory.is_symlink(),'untrusted original process namespace')
        try:
            first=process.generation(directory);raw=process.bounded(directory/'status',65536)
            rows=[line.split()[1:] for line in raw.splitlines() if line.startswith(b'Uid:')]
            require(len(rows)==1 and len(rows[0])==4 and all(value.isdigit() for value in rows[0]),'unknown process UID authority')
            # Linux's stable procfs-audit_loginuid ABI exposes the originating
            # login identity even for a retained privileged sudo descendant.
            login=process.bounded(directory/'loginuid',64).strip()
            require(re.fullmatch(b'[0-9]{1,10}',login) and int(login)<2**32,'original login audit identity is unavailable')
            require(process.generation(directory)==first,'process generation changed before retirement')
            if uid in map(int,rows[0]) or int(login)==uid:
                require(int(directory.name)==main_pid and uid in map(int,rows[0]),'untracked original account or privileged login descendant prevents migration')
        except FileNotFoundError:
            try:directory.lstat()
            except FileNotFoundError:continue
            raise ValueError('live original process has incomplete UID or audit metadata') from None


def original_quiescent(uid):
    original_processes(uid,0)


class Retirement:
    def __init__(self,request,manager_uid,run=legacy.command,privileged_run=privileges.command):
        self.binding=scope(request);self.original=self.binding['legacy'];self.manager_uid=manager_uid;self.run=run;self.privileged_run=privileged_run
    def namespace(self,create=False):
        root_directory(STORE,create=create,mode=0o700)
        require(STORE.lstat().st_mode&0o7777==0o700,'original migration state must remain private')
        paths=list(STORE.iterdir());require(len(paths)<=256,'original migration namespace exceeds its bound')
        for path in paths:
            if path.name in ('retirement','privileges','transfer'):
                require((STORE/'original.json').exists(),'unrecorded migration child cannot be adopted');root_directory(path)
            else:
                require(path.name in ('original.json','manager-confirmed.json','helper-revision.json','run-guard.json') or re.fullmatch(r'\.erpc-[a-f0-9]{32}',path.name),
                        'original migration namespace contains unowned state')
                read(path,1048576,ROOT_UID)
    def saved(self,durable=True):
        self.namespace();value=json_value(read(STORE/'original.json',1048576,ROOT_UID))
        require(isinstance(value,dict) and set(value)=={'schema','binding','observation','manager_uid'}
                and type(value['schema'])is int and value['schema']==1 and value['binding']==self.binding
                and value['manager_uid']==self.manager_uid,'migration belongs to another original operation or manager')
        if durable:sync_file(STORE/'original.json',ROOT_UID);sync_directory(STORE)
        return value
    def reserve(self):
        self.namespace(create=True)
        if (STORE/'original.json').exists():return self.saved()
        import native_migration_guard
        native_migration_guard.other_runs_idle(self.run)
        host.platform_facts(self.original['role'],self.original['network'],self.run)
        observed=legacy.inspect(self.original,self.run,self.manager_uid)
        keys.source(self.original)
        with bls.artifact(self.original):pass
        require(legacy.settings_digest(settings.settings(observed['startup'])) == self.original['settings_sha256'],
                'original configuration differs from the approved migration plan')
        native=observed['service']['process']
        require(native is not None and native['artifact_evidence_matches'] and observed['copy_preflight'] is not None,
                'initial migration needs the qualified live original and separate copy targets')
        original_processes(self.original['historical']['uid'],native['pid']);scheduling(self.original['historical']['uid'],self.run)
        account=privileges.original_accounts(self.privilege_scope(observed))
        revoker=self.revoker(observed)
        revoker.manager(account['manager']);revoker.ssh_effective(False);privileges.sudo_source();privileges.ssh_sources()
        require(revoker.account_status()[1]=='never','original account expiration is not qualified')
        value={'schema':1,'binding':self.binding,'observation':observed,'manager_uid':self.manager_uid}
        atomic(STORE/'original.json',encoded(value));return self.saved()
    def fence_scope(self,observed):
        service=observed['service'];old=self.original['historical']
        return {'intent':self.binding['intent'],'source_sha256':self.original['source_sha256'],
                'machine_id_sha256':old['machine_id_sha256'],'uid':old['uid'],'gid':old['gid'],
                'unit_sha256':observed['unit_sha256'],'commands_sha256':service['commands_sha256'],
                'execution_policy_sha256':service['execution_policy_sha256']}
    def privilege_scope(self,observed):
        return {**{key:self.fence_scope(observed)[key] for key in ('intent','source_sha256','uid','gid')},
                'manager':self.original['management_user'],'manager_uid':self.manager_uid,'ssh_port':self.binding['ssh_port']}
    def host_scope(self,observed):
        self.saved(durable=False);old=self.original['historical']
        keys.source(self.original)
        raw=legacy.read_public('etc/machine-id',maximum=34).strip(b'\r\n')
        require(hashlib.sha256(raw).hexdigest()==old['machine_id_sha256'],'original machine identity changed')
        privileges.original_accounts(self.privilege_scope(observed),partial=True)
        require(legacy.settings_digest(settings.settings(observed['startup'])) == self.original['settings_sha256'],
                'original configuration approval differs')
        require(legacy.startup(legacy.read_public('home/solv/start-validator.sh',uid=old['uid']),self.original)==observed['startup'],
                'original startup bytes changed')
        require(legacy.dropins(self.original)==observed['dropins'],'original service overrides changed')
        current=legacy.storage_observation(old)
        stable=lambda entries:{kind:{key:value for key,value in item.items() if key not in ('device','mount_id')} for kind,item in entries.items()}
        require(stable(current)==stable(observed['storage']),'original filesystem UUID, inode or ownership changed')
        scheduling(old['uid'],self.run)
    def authenticate(self,expected):
        observed=self.saved(durable=False)['observation'];require(expected==self.fence_scope(observed),'original retirement binding changed')
        self.host_scope(observed);fence=self.fence(observed);kind=fence.unit()
        raw=self.run(['/usr/bin/systemctl','show','solv.service','--property=LoadState,ActiveState,SubState,MainPID,ControlPID,NeedDaemonReload,FragmentPath,DropInPaths'])
        values={}
        for row in raw.splitlines():
            key,separator,value=row.partition('=');require(separator and key not in values,'ambiguous original service state');values[key]=value
        if values.get('LoadState')=='masked':
            require(kind=='masked' and values.get('ActiveState') in ('inactive','failed') and values.get('SubState') in ('dead','failed')
                    and values.get('MainPID')=='0' and values.get('ControlPID')=='0' and values.get('NeedDaemonReload')=='no'
                    and values.get('DropInPaths')=='' and values.get('FragmentPath') in ('','/dev/null','/etc/systemd/system/solv.service'),
                    'original masked service retains an active or unknown invocation')
            original_quiescent(expected['uid']);return
        service=legacy.service_properties(self.run,allow_reload=kind=='masked')
        require(legacy.loaded_commands(self.original,service,self.run)==observed['service']['commands_sha256']
                and legacy.loaded_policy(self.original,self.run)==observed['service']['execution_policy_sha256']
                and legacy.loaded_dependencies(self.original,self.run)==observed['service']['dependencies_sha256'],
                'original loaded service command or policy changed')
        native=legacy.process_observation(service,observed['startup'],self.original['historical'],self.original['network'],self.original['artifact_evidence'])
        if native is not None:
            # The same qualified unit may legitimately restart before retirement.
            # Re-prove its CURRENT PID/generation/cgroup/argv/environment above;
            # never replace the original snapshot or authorize a different image.
            # The environment digest includes the current PID/InvocationID, so
            # it is ephemeral after its complete source-derived validation.
            ephemeral={'device','pid','start_ticks','effective_environment_sha256'}
            require({key:value for key,value in native.items() if key not in ephemeral}==
                    {key:value for key,value in observed['service']['process'].items() if key not in ephemeral},'original native image or source layout changed')
            original_processes(expected['uid'],native['pid'])
        else:original_quiescent(expected['uid'])
    def fence(self,observed):
        return fencing.Fence(self.fence_scope(observed),self.authenticate,self.service,self.reconcile)
    def service(self,args):self.run(['/usr/bin/systemctl',*args])
    def reconcile(self,expected):
        self.authenticate(expected);original_quiescent(expected['uid'])
    def revoker(self,observed):
        return privileges.Revocation(self.privilege_scope(observed),lambda _:self.authenticate(self.fence_scope(observed)),original_quiescent,self.privileged_run)
    def retire(self):
        # Authorization is read-only so a persistent storage failure cannot
        # disable the owned-shutdown fallback. The guard/fence publications
        # below still require durable original receipts before proceeding.
        observed=self.saved(durable=False)['observation']
        import native_migration_guard
        self.authenticate(self.fence_scope(observed))
        try:native_migration_guard.install(self)
        except OSError:
            try:
                self.authenticate(self.fence_scope(observed));self.service(['stop','solv.service'])
                original_quiescent(self.original['historical']['uid'])
            except Exception:raise ValueError('managed-run fencing and original shutdown failed; source retained') from None
            raise
        try:self.fence(observed).retire()
        except Exception:
            # Initial durable reservation/mask failure must still attempt only
            # original authenticated shutdown, never report a completed cutover.
            try:
                self.authenticate(self.fence_scope(observed));self.service(['stop','solv.service'])
                original_quiescent(self.original['historical']['uid'])
            except Exception:raise ValueError('original retirement and owned shutdown failed; source retained') from None
            raise
        result=self.revoker(observed).revoke()
        self.authenticate(self.fence_scope(observed));return result
    def confirm(self):
        observed=self.saved()['observation'];fence=self.fence(observed)
        require(fence.saved()['phase']=='retired' and fence.unit()=='masked','original service retirement is incomplete')
        require(self.revoker(observed).verify()['phase']=='revoked','original login retirement is incomplete')
        marker={'binding_sha256':hashlib.sha256(encoded(self.binding)).hexdigest(),'manager_uid':self.manager_uid}
        path=STORE/'manager-confirmed.json'
        if path.exists():require(json_value(read(path,65536,ROOT_UID))==marker,'management confirmation belongs to another operation')
        else:atomic(path,encoded(marker))
        sync_file(path,ROOT_UID);sync_directory(STORE)
        return {'manager_reauthenticated':True,'legacy_retired':True,'copy_authorized':False,'runtime_started':False}


def status(operation):
    """Read recorded progress without an operation lock, private key or mutation."""
    import native_migration_status
    def reader(path,maximum=1048576):
        root_directory(path.parent);return read(path,maximum,ROOT_UID)
    def namespace(path):
        # Missing state is allowed before first reservation, existing ancestors
        # remain subject to the same root-only directory policy.
        existing=path
        while not existing.exists() and not existing.is_symlink():existing=existing.parent
        root_directory(existing)
    return native_migration_status.progress(operation.binding,operation.manager_uid,STORE,host.STATE,reader,namespace)


def control(request,carried):
    public=scope(request);uid=management(public['legacy'],carried)
    action=request['action'];operation=Retirement(request,uid)
    # A delayed old continuation must not touch copied data, retained identity,
    # privileges or source floors after the durable native handoff exists.
    if action not in ('migration-status','migration-finalize'):
        for name in ('migration-complete.json',):
            path=host.STATE/name
            require(not path.exists() and not path.is_symlink(),'completed native ownership refuses stale original migration stages')
    if action=='migration-reserve':
        require(carried,'original migration reservation requires a sealed bundle')
        result=operation.reserve();revision=helpers.publish()
        value={'binding_sha256':hashlib.sha256(encoded(public)).hexdigest(),'revision':revision}
        path=STORE/'helper-revision.json'
        if path.exists():require(json_value(read(path,65536,ROOT_UID))==value,'migration helper revision differs; explicit upgrade required')
        else:atomic(path,encoded(value))
        sync_file(path,ROOT_UID);sync_directory(STORE)
        return {'migration_reserved':True,'intent':result['binding']['intent'],'helper_revision':revision,'copy_authorized':False,'runtime_started':False}
    if action in ('migration-prepare-cutover','migration-finalize'):
        require(carried,'original provider cutover requires its sealed bundle')
        import native_migration_cutover
        value=request['cutover']
        require(isinstance(value,dict) and set(value)=={'receipt','provider_version'},'invalid original cutover acknowledgement')
        cutover=native_migration_cutover.Cutover(operation)
        if action=='migration-prepare-cutover':
            require(value['provider_version'] is None,'preparation cannot claim a promoted provider version')
            return cutover.prepare(value['receipt'])
        return cutover.finalize(value['receipt'],value['provider_version'])
    if action=='migration-retire':
        require(carried,'original retirement requires a sealed bundle');return operation.retire()
    if action=='migration-promote-data':
        require(carried,'original data promotion requires its sealed bundle')
        import native_migration_promote
        return native_migration_promote.Promotion(operation).prepare_data()
    if action=='migration-copy':
        require(carried,'original volume copy requires its sealed bundle')
        import native_migration_transfer
        return native_migration_transfer.Transfer(operation).copy()
    if action=='migration-custody':
        require(carried,'original encrypted retention requires its sealed bundle')
        import native_migration_custody
        return native_migration_custody.Capture(operation).capture()
    require(action!='migration-export','private key export requires its dedicated transport')
    if action=='migration-confirm-manager':
        require(not carried,'management reauthentication requires a fresh direct SSH request');return operation.confirm()
    return status(operation)

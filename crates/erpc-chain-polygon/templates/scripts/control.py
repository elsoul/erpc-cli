#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Owned two-client lifecycle; public RPC identities never register or stake."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys

# BEGIN ERPC TRUSTED IMPORTS
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
# Embedded verbatim in helpers that need sibling modules. Startup uses -I;
# only this checked directory is added, after the standard-library paths.
def trusted_imports(directory):
    import os
    import stat
    import sys
    path = os.fspath(directory)
    if not os.path.isabs(path):
        raise ValueError('helper directory must be an absolute path')
    current = os.path.sep
    for part in path.split(os.path.sep)[1:]:
        if part in ('', '.'):
            continue
        if part == '..':
            # The component being left was already checked as a real root-only
            # directory. Never normalize away an unchecked symlink ancestor.
            current = os.path.dirname(current)
            continue
        current = os.path.join(current, part)
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('helper ancestors must be real root-owned directories')
    path = current
    if path == os.path.sep:
        raise ValueError('the filesystem root is not a helper directory')
    # Do not create root0700 bytecode caches before an unprivileged helper
    # imports the same module. Existing readable caches remain fully checked.
    sys.dont_write_bytecode = True
    pending = [path]
    while pending:
        for child in os.scandir(pending.pop()):
            info = child.stat(follow_symlinks=False)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('helper modules must be writable only by root')
            if stat.S_ISDIR(info.st_mode):
                if (child.name == '__pycache__'
                        and not os.access(child.path, os.X_OK, effective_ids=True)):
                    # No traversal means Python cannot read any cached module
                    # here and must use the checked source. Denied listing alone
                    # (e.g. mode0711) is not sufficient for this exception.
                    continue
                pending.append(child.path)
            elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('helper modules cannot be links or special files')
    if path not in sys.path:
        sys.path.append(path)
# END ERPC TRUSTED IMPORTS
if __name__=='__main__':
    trusted_imports(Path(__file__).absolute().parent)

import artifacts
import host
import identity
import install
import observe
import parent
import volume
from state import ENV,State,canonical,contract,executable,profile_digest,unique


class Control:
    def __init__(self,state=None,source=None,query=observe.http,sleep=observe.time.sleep,ws=observe.websocket,verify=None):
        self.state=state or State()
        self.source=source or Path(__file__).absolute().parent
        self.helpers=install.helper_digest(self.source)
        self.query,self.sleep,self.ws,self.verify=query,sleep,ws,verify

    def expected(self,value):
        if not isinstance(value,dict):raise ValueError('expected immutable Polygon ownership')
        expected=contract(value.get('network'),value.get('owner'),value.get('architecture'),value.get('bor_genesis'),value.get('heimdall_genesis'),value.get('role'),value.get('signer'),value.get('stake_owner'))
        if value!=expected:raise ValueError('unsupported ownership field or role')
        return expected

    def reserve(self,expected):
        state=self.state
        state.ownership(expected,initial=True)
        if state.path('/etc/polygon/contract.json').exists() and state.read('/etc/polygon/contract.json').get('runtime_protocol')!=3:
            raise ValueError('legacy runtime authority requires reviewed storage migration')
        state.namespaces();state.resources(expected);state.accounts.preflight(expected)
        if not state.path('/etc/polygon/contract.json').exists():state.proof.initial()
        for path in ('/etc/polygon','/etc/erpc/polygon','/etc/credstore.encrypted/polygon',
                '/opt/polygon','/opt/polygon/downloads','/opt/polygon/releases','/var/lib/polygon',
                '/usr/local/lib/erpc/polygon/releases'):
            state.protected(path,missing=True)
        directory=state.protected('/etc/polygon',missing=True)
        directory.mkdir(exist_ok=True,mode=0o755);directory.chmod(0o755);host.sync_parents(directory,self.state.root)
        if not (directory/'contract.json').exists():state.write('/etc/polygon/contract.json',dict(expected,runtime_protocol=3))
        state.ownership(expected);volume.reserve(state,expected)
        return {'reserved':True,'network':expected['network'],'role':expected['role']}

    def phase(self,request):
        expected=self.expected(request['contract'])
        if request.get('helpers')!=self.helpers:raise ValueError('operation uses another helper revision')
        profile=self.state.phase(expected,request.get('intent'),request.get('profile'),self.helpers)
        self.state.namespaces()
        return expected,profile

    def prepare(self,request):
        expected=self.expected(request['contract'])
        if request.get('helpers')!=self.helpers:raise ValueError('preparation helper revision differs')
        self.state.namespaces();self.state.accounts.verify(expected)
        if expected['role']=='validator':
            import configure
            shared=parent.transport(self.source/'upstreams.py')
            configure.validator_peers(request['profile'].get('validator'),lambda address:shared.address_allowed(str(address),False))
        if expected['role']=='validator' and request['profile'].get('validator',{}).get('phase')=='active':
            import validator_activation
            validator_activation.require_permit(self.state,expected,request['intent'],request['profile'],self.helpers,before_prepare=True)
        self.state.prepare(expected,request['intent'],request['profile'],self.helpers)
        if request.get('restore_keys') is True:self.restore(expected,self.state.read('/etc/polygon/original-credentials.backup.json'))
        if expected['role']=='validator':
            import broker
            import broker_storage
            import broker_runtime
            broker_storage.reserve(self.state,expected,request['intent'],request['profile'],self.helpers)
            broker.prepare_image(self.state,expected,request['intent'],request['profile'],self.helpers)
            result=install.stage_validator(self.state,expected,request['intent'],request['profile'],self.source)
            broker_runtime.prepare(self.state,expected,request['intent'],request['profile'],self.helpers)
            return {'native_prepared':True,'requires_validator_custody':True,'profile':result['profile'],
                'helpers':self.helpers,'runtime_accounts':self.state.accounts.verify(expected)}
        result=install.prepare(self.state,expected,request['intent'],request['profile'],request['advertise'],self.source)
        if result['helpers']!=self.helpers:raise ValueError('published helper revision differs')
        return {'prepared':True,'profile':result['profile_sha256'],'helpers':self.helpers,
            'runtime_accounts':self.state.accounts.verify(expected)}

    def validator_key(self,request):
        import signer
        expected,profile=self.phase(request)
        if expected['role']!='validator':raise ValueError('RPC nodes cannot import a checkpoint signer')
        self.state.stopped();self.state.accounts.verify(expected)
        prepared=self.state.read('/etc/polygon/native-prepared.json')
        if (prepared.get('contract')!=expected or prepared.get('intent')!=request['intent']
                or prepared.get('profile')!=profile_digest(profile) or prepared.get('helpers')!=self.helpers):
            raise ValueError('original signer transfer requires the exact prepared native pair')
        signer.stage(self.state,expected,request['intent'],profile,self.helpers,request.get('original_signer'))
        return {'original_signer_staged':True}

    def credential(self,request):
        expected,profile=self.phase(request)
        self.state.namespaces();self.state.accounts.verify(expected)
        self.state.stopped()
        if not self.state.path('/etc/polygon/preparing').exists():raise ValueError('credential import requires a fenced preparation')
        raw=canonical(request['credential'])
        if len(raw)>65536:raise ValueError('parent credential exceeds its bound')
        if self.verify:self.verify(request['credential'],profile['parent'])
        else:
            shared=parent.transport(self.source/'upstreams.py')
            parent.Parent(shared,shared.strict_json(raw),profile['parent'],require_public_tls=expected['role']=='validator').verify()
        destination=self.state.protected('/etc/credstore.encrypted/polygon/execution.json',missing=True)
        pending=destination.with_suffix('.pending')
        self.state.protected('/etc/credstore.encrypted/polygon/execution.pending',missing=True)
        self.state.command('systemd-creds','encrypt','--name=execution.json','-',str(pending),input=raw,timeout=60)
        pending.chmod(0o600);host.publish(pending,destination,stop=self.state.root)
        receipt={'contract':expected,'parent':profile['parent'],'cipher_sha256':artifacts.digest(destination)}
        if expected['role']=='validator':receipt['configuration_sha256']=hashlib.sha256(raw).hexdigest()
        self.state.write('/etc/polygon/upstream.json',receipt)
        return {'credential_imported':True}

    def upstream(self,expected,profile):
        receipt=self.state.read('/etc/polygon/upstream.json')
        cipher=self.state.protected('/etc/credstore.encrypted/polygon/execution.json')
        if (receipt.get('contract')!=expected or receipt.get('parent')!=profile['parent']
                or receipt.get('cipher_sha256')!=artifacts.digest(cipher)):
            raise ValueError('parent credential is missing or belongs to another network/owner')
        return receipt

    def installation(self,expected,component=None):
        self.state.ownership(expected);volume.verify(self.state,expected)
        installed=install.installed(self.state,expected,component)
        if installed['helpers']!=self.helpers:
            raise ValueError('another deployment replaced this helper revision; retry the operation')
        identity.history(self.state,expected)
        self.upstream(expected,installed['profile'])
        return installed

    def read_query(self,installed):
        return observe.ValidatorQuery(self.state,installed) if installed['contract']['role']=='validator' else self.query

    def runtime(self,expected,component=None,permit_stopped=False):
        self.state.ownership(expected)
        for name in ('preparing','retired')+(('stopped',) if not permit_stopped else ()):
            if self.state.path('/etc/polygon/'+name).exists():raise ValueError('node startup is fenced')
        self.state.namespaces();self.state.accounts.verify(expected)
        self.state.capacity(expected)
        installed=self.installation(expected,component)
        executable(expected,installed['profile'])
        if expected['role']=='validator':
            import validator_runtime
            validator_runtime.verify(self.state,expected,installed)
        active=self.state.read('/etc/polygon/activation.json')
        if (active.get('contract')!=expected or active.get('profile')!=installed['profile_sha256']
                or active.get('helpers')!=self.helpers):
            raise ValueError('no matching activation authorizes this release pair')
        self.state.firewall().dispatch('guard')
        if expected['role']=='validator' and installed['profile']['validator']['phase']=='active':
            import validator_activation
            validator_activation.require_permit(self.state,expected,active.get('intent'),installed['profile'],self.helpers,credential=True)
            if component in (None,'credential','broker','status'):
                validator_activation.current(self.state,expected,installed['profile'],self.source)
        if component in host.UNITS:self.state.proof.startable(component,installed)
        if expected['role']=='validator' and component=='heimdall':
            import broker_runtime
            manager=broker_runtime.Container(self.state,expected)
            manager.health(manager.token(manager.record()))
        prerequisite={'heimdall':'parent','bor':'heimdall'}.get(component)
        if prerequisite:
            before=self.state.proof.listener(prerequisite,installed)
            query=self.read_query(installed)
            if component=='heimdall':observe.parent(installed['profile'],query)
            elif not observe.heimdall(installed['profile'],query)['ready']:
                raise ValueError('Heimdall must finish synchronizing before Bor can start')
            if self.state.proof.listener(prerequisite,installed)!=before:
                raise ValueError('prerequisite process/listener changed during observation')
        if expected['role']=='validator' and component=='bor':
            import validator_runtime
            validator_runtime.bor_files(self.state,expected,installed)
        return installed

    def broker_condition(self,expected,token):
        import broker_runtime
        installed=self.runtime(expected,'broker')
        original=self.state.accounts.verify(expected)['broker']
        manager=broker_runtime.Container(self.state,expected)
        record=manager.bound(token)
        if record['account']!=original or record['helpers']!=self.helpers:
            raise ValueError('broker unit uses another original runtime generation')
        unit='polygon-broker.service'
        def value(name):return self.state.command('systemctl','show','--property='+name,'--value',unit).stdout.decode().strip()
        if value('User')!='0' or value('Group')!=str(original['gid']) or value('DynamicUser')!='no' or value('SupplementaryGroups')!='':
            raise ValueError('broker root publisher no longer has its exact original recipient')
        return manager,installed

    def broker_start(self,expected,token):
        import broker_runtime
        manager,installed=self.broker_condition(expected,token)
        manager.start_command(token)  # Original CID/config/drain proof BEFORE plaintext publication.
        def authorize():
            current,again=self.broker_condition(expected,token)
            if again!=installed:raise ValueError('broker activation changed while staging original credentials')
            current.start_command(token)
        broker_runtime.stage(self.state,expected,None,installed['profile'],self.helpers,authorize=authorize)
        arguments=manager.start_command(token)
        os.execve(arguments[0],arguments,ENV)

    def credential_condition(self,expected,component):
        if component not in host.UNITS:raise ValueError('unsupported credential recipient')
        # The first ExecCondition runs without EXEC_WRITE_CREDENTIALS on the
        # supported systemd 255. It checks authority only; synchronization and
        # listener prerequisites remain in ExecStartPre for normal retry.
        installed=self.runtime(expected,'credential')
        if expected['role']=='validator':
            # Do not grant a newly active hot credential to an orphan observer
            # sharing the original UID before the later prestart drain check.
            self.state.proof.startable(component,installed)
        original=self.state.accounts.verify(expected)[component]
        unit=host.UNITS[component]
        def value(name):return self.state.command('systemctl','show','--property='+name,'--value',unit).stdout.decode().strip()
        if (value('User')!=str(original['uid']) or value('Group')!=str(original['gid'])
                or value('DynamicUser')!='no' or value('SupplementaryGroups')!=''):
            raise ValueError('loaded credential recipient differs from the original numeric account')
        return {'credential_authority':True}

    def start_units(self,expected):
        # Verify every recipient before requesting any start. Systemd repeats
        # this check as its first condition, before materializing credentials.
        for component in host.UNITS:
            active=self.state.command('systemctl','is-active',host.UNITS[component],check=False).stdout.decode().strip()
            if expected['role']=='validator' and active=='active':
                self.state.proof.listener(component,self.installation(expected,'status'))
            else:self.credential_condition(expected,component)
        native=['polygon-l1-proxy.service','polygon-heimdall.service','polygon-bor.service']
        if expected['role']=='validator':
            import broker_runtime
            manager=broker_runtime.Container(self.state,expected)
            self.broker_condition(expected,manager.token(manager.record()))
            native=['polygon-broker.service',*native,'polygon-peer-bor.timer','polygon-peer-heimdall.timer']
        for unit in native:
            self.state.command('systemctl','reset-failed',unit)
            self.state.command('systemctl','enable',unit)
            self.state.command('systemctl','start','--no-block',unit)
        # A condition 1..254 can make systemctl return success while skipping
        # the unit. Refuse that outcome, including an already-observed 255
        # loader failure; asynchronous synchronization is reported as pending.
        for unit in native:
            result=self.state.command('systemctl','show','--property=Result','--value',unit).stdout.decode().strip()
            condition=self.state.command('systemctl','show','--property=ExecCondition','--value',unit).stdout.decode().strip()
            if result=='exec-condition' or result!='success' and any(int(code)!=0 for code in re.findall(r'\bstatus=([0-9]+)',condition)):
                raise ValueError('credential authority condition failed or skipped the service')


    def activate(self,request):
        expected,profile=self.phase(request)
        self.state.namespaces();self.state.accounts.verify(expected)
        self.state.capacity(expected)
        installed=self.installation(expected)
        if installed['profile']!=profile:raise ValueError('activation differs from the prepared release pair')
        token=request['firewall']
        self.state.firewall().dispatch('require-confirmed',token['run'],token['bundle'])
        self.state.write('/etc/polygon/activation.json',{'contract':expected,'profile':profile_digest(profile),
            'helpers':self.helpers,'intent':request['intent'],'firewall':token})
        self.state.write('/etc/polygon/original-credentials.backup.json',self.backup(expected))
        for name in ('preparing','retired','stopped'):
            host.unlink(self.state.protected('/etc/polygon/'+name,missing=True),self.state.root)
        self.start_units(expected)
        return {'startup_requested':True,'service_readiness':'pending; inspect status','synchronizing':True,'network':expected['network']}

    def stop(self,expected,retire=False):
        self.state.ownership(expected)
        failure=None
        try:
            host.fence(self.state.protected('/etc/polygon/stopped',missing=True),self.state.root)
            if retire:host.fence(self.state.protected('/etc/polygon/retired',missing=True),self.state.root)
        except Exception as error:failure=error
        # Try both independent cancellation barriers, even if the first write
        # fails. Still disable/drain known units on storage failure; report the
        # error and retain ingress rather than claiming durable cancellation.
        try:self.state.invalidate('retired' if retire else 'stopped')
        except Exception as error:
            if failure is None:failure=error
        self.state.stop(disable=retire or failure is not None)
        if failure is not None:raise failure
        if retire:self.state.firewall().dispatch('teardown')
        return {'stopped':True,'retired':retire,'data_retained':True}

    def start(self,expected,restart=False):
        installed=self.runtime(expected,permit_stopped=True)
        if restart:
            host.fence(self.state.protected('/etc/polygon/stopped',missing=True),self.state.root)
            self.state.stop()
        else:self.state.proof.can_start(installed)
        # An explicit start may clear a stop fence left by failed intent
        # invalidation. Revoke that pending deployment durably first.
        self.state.invalidate('manual-start')
        host.unlink(self.state.protected('/etc/polygon/stopped',missing=True),self.state.root)
        self.start_units(expected)
        return {'startup_requested':True,'service_readiness':'pending; inspect status','synchronizing':True}

    def status(self,expected):
        self.state.ownership(expected)
        phases={name:self.state.path('/etc/polygon/'+name).exists() for name in ('preparing','stopped','retired')}
        result={'network':expected['network'],'role':expected['role'],'fences':phases,'ready':False}
        if expected['role']=='validator':result.update(runtime_ready=False,observer_ready=False,validator_active=False)
        try:
            installed=self.installation(expected,'status')
            if expected['role']=='validator':result['phase']=installed['profile']['validator']['phase']
            before={}
            for name in host.UNITS:
                try:before[name]=self.state.proof.listener(name,installed)
                except Exception:before[name]=None
            transport=self.read_query(installed)
            def query(port,path='/',payload=None):
                component={8545:'bor',9545:'parent',26657:'heimdall',1317:'heimdall'}.get(port)
                if component is None or before[component] is None:raise ValueError('unowned local observation refused')
                return transport(port,path,payload)
            result.update(observe.status(installed['profile'],query,self.sleep,
                None if expected['role']=='validator' else lambda chain:self.ws(chain) if before['bor'] is not None else False))
            owned={}
            for name in host.UNITS:
                try:owned[name]=before[name] is not None and self.state.proof.listener(name,installed)==before[name]
                except Exception:owned[name]=False
            result['service_ownership']=owned
            if expected['role']=='validator':
                import broker_runtime
                manager=broker_runtime.Container(self.state,expected)
                result['broker']=manager.health(manager.token(manager.record()))
                owned['broker']=result['broker']['ready']
            result['ready']=result['ready'] and all(owned.values())
            result['releases']={name:value['tag'] for name,value in installed['profile']['releases'].items()}
            self.runtime(expected,'status')
            result['ready']=result['ready'] and not any(phases.values())
            if expected['role']=='validator':
                result['runtime_ready']=result['ready']
                result['observer_ready']=result['ready'] and result['phase']=='observing'
                result['validator_active']=result['ready'] and result['phase']=='active'
                result['ready']=result['validator_active']
        except Exception:
            result['ready']=False
            result['installation']='not activated, incomplete or unavailable'
        return result

    def backup(self,expected):
        self.state.ownership(expected)
        original=identity.receipt(self.state,expected)
        installed=self.installation(expected,'status')
        upstream=self.upstream(expected,installed['profile'])
        contents={name:base64.b64encode(self.state.protected('/etc/credstore.encrypted/polygon/original/'+name).read_bytes()).decode()
                  for name in (*identity.files(expected),'initial-state.json')}
        cipher=self.state.protected('/etc/credstore.encrypted/polygon/execution.json').read_bytes()
        value={'format':1,'contract':expected,'identity':original,'files':contents,
                'upstream':upstream,'upstream_cipher':base64.b64encode(cipher).decode()}
        if expected['role']=='validator':
            import validator_runtime
            value['validator_dependencies']=validator_runtime.backup_custody(self.state,expected)
        return value

    def restore(self,expected,backup):
        self.state.ownership(expected);volume.verify(self.state,expected)
        self.state.stopped()
        if not any(self.state.path('/etc/polygon/'+name).exists() for name in ('preparing','stopped','retired')):
            raise ValueError('original-key restore requires an explicit stopped fence')
        original=self.state.read('/etc/polygon/identity.json')
        initialized={'contract':expected,'identity_sha256':hashlib.sha256(canonical(original)).hexdigest(),'state':'initialized'}
        if self.state.read('/etc/polygon/history.json')!=initialized:
            raise ValueError('retained consensus initialization proof is missing')
        if (not isinstance(backup,dict) or backup.get('format')!=1 or backup.get('contract')!=expected
                or backup.get('identity')!=original or original.get('contract')!=expected
                or set(backup.get('files',{}))!=set((*identity.files(expected),'initial-state.json'))):
            raise ValueError('backup does not match the retained original public identity')
        # Retain the actual consensus signing state. A backup never supplies a
        # replacement for mutable history, even when the RPC node was unregistered.
        history=self.state.path('/var/lib/polygon/heimdall/data/priv_validator_state.json')
        if history.is_symlink() or not history.is_file() or history.stat().st_nlink!=1:
            raise ValueError('activated consensus history is missing; explicit offline recovery is required')
        decoded={}
        for name,encoded in backup['files'].items():
            if not isinstance(encoded,str) or len(encoded)>90000:raise ValueError('backup field exceeds its bound')
            value=base64.b64decode(encoded,validate=True)
            wanted=original['initial_state_sha256'] if name=='initial-state.json' else original['ciphertexts'][name]
            if hashlib.sha256(value).hexdigest()!=wanted:raise ValueError('backup ciphertext differs from the original identity')
            if name!='initial-state.json':
                # Host-bound systemd encryption must decrypt on this original
                # host. Do not capture or print the plaintext validation output.
                self.state.run(['systemd-creds','decrypt','--name='+name,'-','-'],input=value,
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=30,env=ENV)
            decoded[name]=value
        upstream=self.state.read('/etc/polygon/upstream.json')
        parent_cipher=None
        if backup.get('upstream')==upstream:
            encoded=backup.get('upstream_cipher')
            if not isinstance(encoded,str) or len(encoded)>90000:raise ValueError('parent ciphertext exceeds its bound')
            parent_cipher=base64.b64decode(encoded,validate=True)
            if hashlib.sha256(parent_cipher).hexdigest()!=upstream['cipher_sha256']:
                raise ValueError('parent ciphertext changed')
            self.state.run(['systemd-creds','decrypt','--name=execution.json','-','-'],input=parent_cipher,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=30,env=ENV)
        # A later parent-credential rotation must not invalidate recovery of the
        # unchanged original node identities or roll back the rotated secret.
        # Normal deploy imports the currently selected parent field afterwards.
        directory=self.state.protected('/etc/credstore.encrypted/polygon/original',missing=True)
        directory.mkdir(parents=True,exist_ok=True,mode=0o700)
        # All input and host binding are checked before replacing a missing or
        # corrupted ciphertext. Crash/retry may complete individual atomic files;
        # the stopped fence prevents using a partially restored set.
        for name,value in decoded.items():
            destination=self.state.protected('/etc/credstore.encrypted/polygon/original/'+name,missing=True)
            temporary=destination.with_suffix('.restore')
            self.state.protected('/etc/credstore.encrypted/polygon/original/'+temporary.name,missing=True)
            temporary.write_bytes(value);temporary.chmod(0o600);host.publish(temporary,destination,stop=self.state.root)
        self.state.write('/etc/credstore.encrypted/polygon/original/receipt.json',original)
        self.state.write('/etc/credstore.encrypted/polygon/original/home-state.json',initialized)
        if parent_cipher is not None:
            destination=self.state.protected('/etc/credstore.encrypted/polygon/execution.json',missing=True)
            temporary=destination.with_suffix('.restore')
            self.state.protected('/etc/credstore.encrypted/polygon/execution.restore',missing=True)
            temporary.write_bytes(parent_cipher);temporary.chmod(0o600);host.publish(temporary,destination,stop=self.state.root)
        identity.receipt(self.state,expected)
        if expected['role']=='validator':
            import validator_runtime
            validator_runtime.restore_custody(self.state,expected,backup.get('validator_dependencies'))
        return {'restored_original_keys':True,'parent_restored':parent_cipher is not None,'stopped':True,'history_retained':True}

    def logs(self,expected,request):
        self.state.ownership(expected)
        component=request.get('component','all');lines=request.get('lines',100);follow=request.get('follow',False)
        units=dict(host.UNITS)
        if expected['role']=='validator':units['broker']='polygon-broker.service'
        if component not in (*units,'all') or type(lines) is not int or not 1<=lines<=10000 or type(follow) is not bool:
            raise ValueError('invalid journal selection')
        args=['journalctl','--no-pager','--lines='+str(lines)]
        for name in units.values() if component=='all' else [units[component]]:args.extend(['--unit',name])
        if follow:args.append('--follow')
        os.execve('/usr/bin/journalctl',args,ENV)

    def dispatch(self,request):
        if not isinstance(request,dict):raise ValueError('expected Polygon operation object')
        expected=self.expected(request.get('contract'));action=request.get('action')
        action={'start-v2':'start','stop-v2':'stop','restart-v2':'restart','start-v3':'start','restart-v3':'restart'}.get(action,action)
        if action=='reserve':return self.reserve(expected)
        self.state.ownership(expected)
        if action=='provision-accounts':
            self.state.namespaces()
            self.state.accounts.provision(expected)
            return {'accounts':'established'}
        if action=='publish-controller':
            self.state.namespaces();self.state.accounts.verify(expected);volume.verify(self.state,expected)
            executable(expected,request['profile'])
            if request.get('helpers')!=self.helpers:raise ValueError('public controller handoff differs from carried source')
            self.state.reserve_target(expected,request['profile'],self.helpers,failure=lambda:self.stop(expected))
            try:return {'controller_published':install.publish_helpers(self.state,self.source)}
            except Exception:
                self.stop(expected)
                raise
        if action=='broker-daemon-guard':
            import broker_docker
            return broker_docker.start_allowed(self.state,expected)
        if action=='guard':
            self.state.namespaces()
            return {'owned':True}
        if action=='phase':
            expected,profile=self.phase(request)
            installed=self.installation(expected)
            if installed['profile']!=profile:raise ValueError('firewall phase differs from installed pair')
            self.state.stopped()
            return {'prepared_for_firewall':True}
        if action=='confirm':
            self.phase(request)
            token=request['firewall']
            self.state.firewall().confirm(token['run'],token['bundle'])
            return {'firewall_confirmed':True}
        if action=='prepare':return self.prepare(request)
        if action=='registration':
            import validator_activation
            return validator_activation.registration(self,request)
        if action=='authorize-active':
            import validator_activation
            return validator_activation.authorize(self,request)
        if action=='validator-key':return self.validator_key(request)
        if action=='validator-finalize':
            import validator_runtime
            return validator_runtime.finalize(self,request)
        if action=='credential':return self.credential(request)
        if action=='seal':
            expected,profile=self.phase(request)
            install.seal(self.state,expected,request['intent'],profile)
            return {'sealed':True}
        if action=='activate':return self.activate(request)
        if action=='status':return self.status(expected)
        if action=='recover-original':
            self.stop(expected)
            return self.restore(expected,self.state.read('/etc/polygon/original-credentials.backup.json'))
        if action=='backup':return self.backup(expected)
        if action=='restore':return self.restore(expected,request.get('backup'))
        if action=='logs':return self.logs(expected,request)
        if action in ('stop','destroy'):return self.stop(expected,action=='destroy')
        if action in ('start','restart'):return self.start(expected,action=='restart')
        raise ValueError('unsupported Polygon lifecycle operation')


def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    mode=sys.argv[1] if len(sys.argv)>1 else ''
    controller=Control()
    if mode=='logs' and len(sys.argv)==10 and sys.argv[9] in ('follow','once'):
        controller.logs(contract(*sys.argv[2:7]),{'component':sys.argv[7],'lines':int(sys.argv[8]),'follow':sys.argv[9]=='follow'})
        return
    if mode=='logs' and len(sys.argv)==13 and sys.argv[7]=='validator' and sys.argv[12] in ('follow','once'):
        controller.logs(contract(*sys.argv[2:10]),{'component':sys.argv[10],'lines':int(sys.argv[11]),'follow':sys.argv[12]=='follow'})
        return
    if mode=='firewall' and len(sys.argv)==3:
        expected=controller.expected(json.loads(sys.argv[2],object_pairs_hook=unique))
        controller.state.ownership(expected)
        # The checked common helper owns cold-boot load's operation lock.
        # A second descriptor held here would make its LOCK_NB acquisition fail.
        controller.state.firewall().dispatch('load')
        return
    if mode=='credential-condition' and len(sys.argv)==4 and sys.argv[2] in ('bor','heimdall','parent'):
        try:controller.credential_condition(controller.expected(json.loads(sys.argv[3],object_pairs_hook=unique)),sys.argv[2])
        except Exception:raise SystemExit(255) from None
        return
    if mode in ('broker-condition','broker-start','broker-stop') and len(sys.argv)==4:
        expected=controller.expected(json.loads(sys.argv[2],object_pairs_hook=unique))
        token=json.loads(sys.argv[3],object_pairs_hook=unique)
        if mode=='broker-stop':
            import broker_runtime
            broker_runtime.Container(controller.state,expected).stop(token)
        elif mode=='broker-condition':
            try:controller.broker_condition(expected,token)
            except Exception:raise SystemExit(255) from None
        else:controller.broker_start(expected,token)
        return
    if mode=='peer-publish' and len(sys.argv)==4 and sys.argv[2] in ('bor','heimdall'):
        import native_authority
        expected=controller.expected(json.loads(sys.argv[3],object_pairs_hook=unique))
        native_authority.publish(controller.state,expected,sys.argv[2],lambda:controller.runtime(expected,'peer'))
        return
    if mode=='runtime' and len(sys.argv)==4 and sys.argv[2] in ('bor','heimdall','parent'):
        controller.runtime(controller.expected(json.loads(sys.argv[3],object_pairs_hook=unique)),sys.argv[2])
        return
    if mode not in ('request','within-run') or len(sys.argv)!=2:raise ValueError('invalid controller invocation')
    raw=sys.stdin.buffer.read(1048577)
    if len(raw)>1048576:raise ValueError('operation input exceeds its bound')
    request=json.loads(raw,object_pairs_hook=unique)
    if mode=='within-run' or request.get('action')=='logs':result=controller.dispatch(request)
    else:
        with controller.state.locked():result=controller.dispatch(request)
    print(json.dumps(result,sort_keys=True,separators=(',',':')))


if __name__=='__main__':
    try:main()
    except Exception:
        print('Polygon operation refused: ownership, deployment state or native verification failed',file=sys.stderr)
        raise SystemExit(1)

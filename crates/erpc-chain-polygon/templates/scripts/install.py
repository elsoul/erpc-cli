# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Stopped-host preparation of an authenticated, network-bound release pair."""
import hashlib
import json
import os
import shutil
import shlex
from pathlib import Path
import re
import subprocess
import uuid
import artifacts
import host
import configure
import identity
import parent
import launch
from state import canonical,profile_digest,target,unique


SCRIPTS=('accounts.py','admission.py','artifacts.py','broker.py','broker_docker.py','broker_runtime.py','broker_storage.py','checkpoint.py','configure.py','control.py','gateway.py','host.py','host_resources.py','identity.py','install.py','launch.py','local_tls.py','native_authority.py','native_peer.py',
         'observe.py','parent.py','signer.py','signatures.py','state.py','upstreams.py','validator_activation.py','validator_runtime.py','volume.py')


def helper_digest(directory):
    digest=hashlib.sha256()
    for name in SCRIPTS:
        path=directory/name
        if path.is_symlink() or not path.is_file():raise ValueError('helper revision is incomplete or redirected')
        with path.open('rb') as stream:
            for block in iter(lambda:stream.read(128*1024),b''):digest.update(block)
    return digest.hexdigest()


def publish_helpers(state,source):
    sha=helper_digest(source)
    base=state.protected('/usr/local/lib/erpc/polygon')
    releases=state.protected('/usr/local/lib/erpc/polygon/releases')
    for directory in (base,releases):
        if not directory.is_dir() or directory.stat().st_mode&0o005!=0o005:
            raise ValueError('the public helper namespace must remain traversable')
    if base.is_symlink() or releases.is_symlink():raise ValueError('helper publication cannot follow a namespace link')
    destination=releases/sha
    if destination.is_symlink():raise ValueError('an immutable helper revision cannot be redirected')
    if not destination.exists():
        pending=releases/(sha+'.pending')
        if pending.is_symlink():raise ValueError('helper staging cannot be a symlink')
        if pending.exists():shutil.rmtree(pending)  # Unpublished public source only.
        pending.mkdir(mode=0o755);pending.chmod(0o755)
        for name in SCRIPTS:
            target=pending/name
            target.write_bytes((source/name).read_bytes());target.chmod(0o644)
        if helper_digest(pending)!=sha:raise ValueError('helper revision changed while publishing')
        host.publish(pending,destination,tree=True,stop=state.root)
    if helper_digest(destination)!=sha:raise ValueError('existing immutable helper revision is damaged')
    temporary=base/'current.pending'
    if temporary.exists() or temporary.is_symlink():temporary.unlink()
    temporary.symlink_to('/usr/local/lib/erpc/polygon/releases/'+sha,target_is_directory=True)
    temporary.replace(base/'current');host.sync_parents(base,state.root)
    return sha



def unit_names(expected):
    names={'polygon-bor','polygon-heimdall','polygon-l1-proxy'}
    if expected['role']=='validator':
        names.update(('polygon-broker','polygon-peer-bor','polygon-peer-heimdall',
            'polygon-peer-bor.timer','polygon-peer-heimdall.timer'))
    return names


def unit_path(name):return '/etc/systemd/system/'+name+('' if name.endswith('.timer') else '.service')


def validator_credentials(component,profile):
    base='/etc/credstore.encrypted/polygon/'
    if component=='bor':
        result={'bor-nodekey':base+'original/bor-nodekey'}
        if profile['validator']['phase']=='active':result['bor-password']=base+'original/bor-password'
    elif component=='parent':
        result={'execution.json':base+'execution.json','polygon-bor-auth':base+'bor-auth',
            'polygon-gateway-tls':base+'local-tls/polygon-gateway-tls'}
    else:
        result={'heimdall-node-key.json':base+'original/heimdall-node-key.json',
            'heimdall-validator-key.json':base+'heimdall-runtime-key.json',
            'comet-certificate':base+'local-tls/comet-certificate','comet-private-key':base+'local-tls/comet-private-key',
            'native-app.toml':base+'native-app.toml'}
    return ['LoadCredentialEncrypted='+name+':'+path for name,path in result.items()]


def installed(state,expected,component=None,require_units=True,pending_configuration=False):
    if pending_configuration:
        if not state.protected('/etc/polygon/preparing',missing=True).exists():raise ValueError('public configuration recovery requires a preparation fence')
        state.stopped()
    receipt=state.read('/etc/polygon/installed.json')
    profile=target(expected,receipt['profile'])
    if receipt.get('contract')!=expected or receipt.get('profile_sha256')!=profile_digest(profile):
        raise ValueError('installed release pair belongs to another ownership/profile')
    if set(receipt.get('binaries',{}))!={'bor','heimdall'}:
        raise ValueError('both native release records are required')
    for name,record in receipt['binaries'].items():
        wanted='/opt/polygon/releases/'+name+'-'+profile['releases'][name]['tag']+'-'+expected['architecture']
        if record['directory']!=wanted:
            raise ValueError('installed native path differs from the reviewed release')
        binary=state.protected(wanted+'/usr/bin/'+('bor' if name=='bor' else 'heimdalld'))
        if binary.is_symlink() or not binary.is_file():raise ValueError('installed native binary is missing or redirected')
        if component in (None,name):
            if artifacts.digest(binary)!=record['sha256']:
                raise ValueError('installed native binary changed after authentication')
    required={'/etc/polygon/launch.json','/etc/polygon/bor.toml','/var/lib/polygon/heimdall/config/config.toml',
        '/var/lib/polygon/heimdall/config/app.toml','/var/lib/polygon/heimdall/config/client.toml','/var/lib/polygon/genesis/'+expected['network']+'.json'}
    helpers=receipt.get('helpers','')
    if not re.fullmatch('[a-f0-9]{64}',helpers):raise ValueError('installed helper revision is missing')
    helper_root='/usr/local/lib/erpc/polygon/releases/'+helpers
    if helper_digest(state.path(helper_root))!=helpers:raise ValueError('installed helper revision changed')
    required.update(helper_root+'/'+name for name in SCRIPTS)
    if set(receipt.get('files',{}))!=required:
        raise ValueError('installed configuration/controller manifest is incomplete')
    for path,sha in receipt['files'].items():
        # Every script/config path was recorded while stopped; no arbitrary
        # receipt-selected paths can become a root file-reading oracle.
        allowed=path in ('/etc/polygon/launch.json','/etc/polygon/bor.toml','/var/lib/polygon/heimdall/config/config.toml',
            '/var/lib/polygon/heimdall/config/app.toml','/var/lib/polygon/heimdall/config/client.toml','/var/lib/polygon/genesis/'+expected['network']+'.json')
        allowed=allowed or re.fullmatch(re.escape(helper_root)+'/[a-z_-]+[.]py',path) is not None
        if not allowed:raise ValueError('unexpected installed artifact path')
        if path.endswith('/genesis/'+expected['network']+'.json') and component not in (None,'heimdall'):
            continue  # Only Heimdall consumes this large immutable file.
        file=state.path(path)
        replaceable=path in ('/etc/polygon/launch.json','/etc/polygon/bor.toml',
            '/var/lib/polygon/heimdall/config/config.toml','/var/lib/polygon/heimdall/config/app.toml','/var/lib/polygon/heimdall/config/client.toml')
        state.protected(path)
        if file.is_symlink() or not file.is_file() or (not (pending_configuration and replaceable) and artifacts.digest(file)!=sha):
            raise ValueError('installed configuration or controller differs from the recorded deployment')
    launched=state.read('/etc/polygon/launch.json')
    wanted=launch.metadata(expected,profile,receipt['binaries'])
    if pending_configuration:
        if launched.get('network')!=expected['network'] or launched.get('role','fullnode')!=expected['role']:
            raise ValueError('unfinished public launch changed its immutable network or role')
        for name in ('bor','heimdall'):
            arguments=launch.arguments(name,launched)
            if not arguments[0].endswith('-'+expected['architecture']+'/usr/bin/'+('bor' if name=='bor' else 'heimdalld')):
                raise ValueError('unfinished public executable changed original architecture')
    elif launched!=wanted:raise ValueError('public launch metadata differs from the reviewed pair')
    if expected['role']=='validator':
        issuer_dir=state.protected('/etc/polygon/empty-ca')
        if not issuer_dir.is_dir() or any(issuer_dir.iterdir()):raise ValueError('native issuer directory must remain sealed and empty')
    if require_units:
        names=unit_names(expected)
        if set(receipt.get('units',{}))!=names:raise ValueError('service definitions have not been sealed')
        for name,sha in receipt['units'].items():
            if artifacts.digest(state.path(unit_path(name)))!=sha:
                raise ValueError('managed service definition changed after activation')
    return receipt


def service_guard(controller,path):
    source=controller.read_text()
    trust=source.split('# BEGIN ERPC TRUSTED IMPORTS\n',1)[1].split('# END ERPC TRUSTED IMPORTS',1)[0]
    directory=path.rsplit('/',1)[0]
    program=trust+"\nimport runpy\ntrusted_imports('"+directory+"')\nrunpy.run_path('"+path+"', run_name='__main__')"
    return "/usr/bin/python3 -I -c \"exec(bytes.fromhex('"+program.encode().hex()+"'))\""


def service_condition(controller,path):
    checked=service_guard(controller,path)
    prefix='/usr/bin/python3 -I -c "'
    if not checked.startswith(prefix) or not checked.endswith('"'):raise ValueError('invalid checked condition command')
    expression=checked[len(prefix):-1]
    program="try:\n    "+expression+"\nexcept SystemExit as error:\n    if error.code not in (None, 0):\n        raise SystemExit(255) from None\nexcept BaseException:\n    raise SystemExit(255) from None\n"
    return "/usr/bin/python3 -I -c \"exec(bytes.fromhex('"+program.encode().hex()+"'))\""


def seal(state,expected,intent,profile):
    state.phase(expected,intent,profile);state.stopped()
    receipt=installed(state,expected,require_units=False)
    units={}
    accounts=state.accounts.verify(expected)
    for name,component in [('polygon-bor','bor'),('polygon-heimdall','heimdall'),('polygon-l1-proxy','parent')]:
        path=state.path('/etc/systemd/system/'+name+'.service')
        text=path.read_text()
        command='ExecStart=/usr/bin/python3 -I /usr/local/lib/erpc/polygon/releases/'+receipt['helpers']+'/'+('parent.py '+profile['parent'] if component=='parent' else 'launch.py '+component)
        lines=text.splitlines()
        if lines.count(command)!=1:
            raise ValueError('service definition does not use the fixed managed launcher')
        uid,gid=str(accounts[component]['uid']),str(accounts[component]['gid'])
        if lines.count('User='+uid)!=1 or lines.count('Group='+gid)!=1:
            raise ValueError('managed clients require their original numeric UID/GID')
        if any(lines.count(setting)!=1 for setting in ('SupplementaryGroups=','DynamicUser=no','LimitCORE=0')):
            raise ValueError('managed credential recipients require fixed groups and disabled core dumps')
        guards=[line.split('=',1)[1] for line in lines if line.startswith('ExecStartPre=')]
        controller='/usr/local/lib/erpc/polygon/releases/'+receipt['helpers']+'/control.py'
        expected_guard=shlex.split('+'+service_guard(state.protected(controller),controller))+['runtime',component]
        conditions=[line.split('=',1)[1] for line in lines if line.startswith('ExecCondition=')]
        expected_condition=shlex.split('+'+service_condition(state.protected(controller),controller))+['credential-condition',component]
        if len(conditions)!=1:raise ValueError('exactly one first credential-free condition is required')
        condition=shlex.split(conditions[0])
        if condition[:-1]!=expected_condition or json.loads(condition[-1],object_pairs_hook=unique)!=expected:
            raise ValueError('credential condition differs from the owned original identity')
        if len(guards)!=1:raise ValueError('one immutable runtime ownership/capacity guard is required')
        arguments=shlex.split(guards[0])
        if arguments[:-1]!=expected_guard or json.loads(arguments[-1],object_pairs_hook=unique)!=expected:
            raise ValueError('runtime guard differs from the owned network/identity')
        if expected['role']=='validator':
            observed=[line for line in lines if line.startswith('LoadCredential')]
            if sorted(observed)!=sorted(validator_credentials(component,profile)):
                raise ValueError('validator service would receive the wrong phase or native credential')
        units[name]=artifacts.digest(path)
    if expected['role']=='validator':seal_validator_units(state,expected,receipt,units)
    receipt['units']=units
    state.write('/etc/polygon/installed.json',receipt)
    return installed(state,expected)



def seal_validator_units(state,expected,receipt,units):
    import broker_runtime
    original=broker_runtime.container_record(state,expected)
    token=broker_runtime.Container.token(original)
    if original['helpers']!=receipt['helpers'] or original['account']!=state.accounts.verify(expected)['broker']:
        raise ValueError('broker unit cannot adopt another container generation')
    controller='/usr/local/lib/erpc/polygon/releases/'+receipt['helpers']+'/control.py'
    source=state.protected(controller)
    guard=shlex.split(service_guard(source,controller));condition=shlex.split(service_condition(source,controller))
    def command(lines,key,prefix,mode,arguments):
        found=[shlex.split(line.split('=',1)[1]) for line in lines if line.startswith(key+'=')]
        if len(found)!=1 or found[0][:len(prefix)+1]!=[*prefix,mode] or len(found[0])!=len(prefix)+1+len(arguments):
            raise ValueError('validator auxiliary service uses another checked entrypoint')
        for observed,wanted in zip(found[0][len(prefix)+1:],arguments):
            if (json.loads(observed,object_pairs_hook=unique) if isinstance(wanted,dict) else observed)!=wanted:
                raise ValueError('validator auxiliary service has another original operation binding')
    path=state.protected(unit_path('polygon-broker'));lines=path.read_text().splitlines()
    for setting in ('User=0','Group='+str(original['account']['gid']),'SupplementaryGroups=','DynamicUser=no',
            'LimitCORE=0','RuntimeDirectory=erpc-polygon-broker','RuntimeDirectoryMode=0750','RuntimeDirectoryPreserve=no'):
        if lines.count(setting)!=1:raise ValueError('broker root publication recipient or runtime namespace differs')
    if any(line.startswith('LoadCredential') for line in lines):raise ValueError('broker must decrypt only after original account verification')
    command(lines,'ExecCondition',condition,'broker-condition',[expected,token])
    command(lines,'ExecStart',guard,'broker-start',[expected,token])
    command(lines,'ExecStop',guard,'broker-stop',[expected,token])
    units['polygon-broker']=artifacts.digest(path)
    for component in ('bor','heimdall'):
        name='polygon-peer-'+component;path=state.protected(unit_path(name));lines=path.read_text().splitlines()
        if any(lines.count(setting)!=1 for setting in ('Type=oneshot','User=0','Group=0','LimitCORE=0')):
            raise ValueError('peer publisher must remain a bounded root oneshot')
        command(lines,'ExecStart',guard,'peer-publish',[component,expected])
        units[name]=artifacts.digest(path)
        timer=state.protected(unit_path(name+'.timer'));lines=timer.read_text().splitlines()
        if any(lines.count(setting)!=1 for setting in ('OnBootSec=15s','OnUnitActiveSec=15s','AccuracySec=1s','Persistent=false','Unit='+name+'.service')):
            raise ValueError('peer refresh timer differs from the bounded original publisher')
        units[name+'.timer']=artifacts.digest(timer)


def cached(state,pin):
    directory=state.path('/opt/polygon/downloads');directory.mkdir(parents=True,exist_ok=True)
    path=directory/pin['sha256']
    if path.is_symlink():raise ValueError('artifact cache cannot contain a redirected file')
    if path.exists():
        try:artifacts.authenticate(path,pin)
        except ValueError:path.rename(path.with_name(path.name+'.invalid-'+uuid.uuid4().hex))
    artifacts.fetch(pin,path)
    return path


def native_artifacts(state,expected,intent,profile):
    state.phase(expected,intent,profile)
    state.stopped();state.capacity(expected)
    architecture=expected['architecture']
    verifier=cached(state,profile['verifier']['assets'][architecture])
    verifier.chmod(0o755)
    releases={}
    for name in ('heimdall','bor'):
        release=profile['releases'][name];pins=release['assets'][architecture]
        files={key:cached(state,pin) for key,pin in pins.items()}
        artifacts.signature(verifier,files['package'],files['signature'],files['certificate'],
            release['certificate_identity'],release['commit'],state.run)
        directory='/opt/polygon/releases/'+name+'-'+release['tag']+'-'+architecture
        actual=state.path(directory);actual.parent.mkdir(parents=True,exist_ok=True)
        binary=artifacts.extract(files['package'],actual,'bor' if name=='bor' else 'heimdalld',state.run)
        state.protected('/'+str(binary.relative_to(state.root)))
        artifacts.native_version(binary,name,release,architecture,state.run,client_config=configure.client(profile))
        releases[name]={'directory':directory,'sha256':artifacts.digest(binary)}
    # Genesis belongs on the provisioned data volume, not the OS partition.
    genesis_dir=state.path('/var/lib/polygon/genesis');genesis_dir.mkdir(mode=0o755,exist_ok=True)
    genesis=genesis_dir/(expected['network']+'.json')
    artifacts.fetch(profile['heimdall_genesis'],genesis)
    genesis.chmod(0o644)
    import tomllib  # Managed Ubuntu 24.04 supplies Python 3.12.
    inputs={name:tomllib.loads(cached(state,pin).read_text()) for name,pin in profile['configs'].items()}
    state.phase(expected,intent,profile);state.stopped()
    return releases,inputs


def stage_validator(state,expected,intent,profile,source_dir):
    if expected['role']!='validator':raise ValueError('native signer staging requires validator ownership')
    releases,_inputs=native_artifacts(state,expected,intent,profile)
    helpers=publish_helpers(state,source_dir)
    state.phase(expected,intent,profile,helpers);state.stopped()
    receipt={'contract':expected,'intent':intent,'profile':profile_digest(profile),'helpers':helpers,'binaries':releases}
    state.write('/etc/polygon/native-prepared.json',receipt)
    return receipt


def prepare(state,expected,intent,profile,advertise,source_dir):
    releases,inputs=native_artifacts(state,expected,intent,profile)
    import tomllib
    transport=parent.transport(source_dir/'upstreams.py')
    bor,consensus,app=configure.profiles(profile,inputs['bor'],inputs['heimdall_config'],inputs['heimdall_app'],advertise,
        lambda address:transport.address_allowed(str(address),False),validator=profile.get('validator'))
    for text in (bor,consensus,app):tomllib.loads(text)
    heimdalld=state.path(releases['heimdall']['directory']+'/usr/bin/heimdalld')
    validator=None
    if expected['role']=='validator':
        import signer
        staged=state.read('/etc/polygon/native-prepared.json')
        wanted={'contract':expected,'intent':intent,'profile':profile_digest(profile),'helpers':helper_digest(source_dir),'binaries':releases}
        if staged!=wanted:raise ValueError('signer conversion differs from the prepared native release pair')
        if not state.path('/etc/credstore.encrypted/polygon/original').exists():
            validator=signer.material(state,expected,intent,profile,
                state.path(releases['bor']['directory']+'/usr/bin/bor'),heimdalld,app)
    if validator is None:identity.initialize(state,expected,heimdalld,profile)
    else:identity.initialize(state,expected,heimdalld,profile,validator=validator)
    identity.home(state,expected,profile)
    native_home=state.path('/var/lib/polygon/heimdall')
    bor_data=state.path('/var/lib/polygon/bor/data')
    bor_data.mkdir(parents=True,exist_ok=True,mode=0o700)
    accounts=state.accounts.verify(expected)
    bor_owner=str(accounts['bor']['uid'])+':'+str(accounts['bor']['gid'])
    state.command('chown',bor_owner,str(bor_data.parent),str(bor_data))
    state.command('chmod','0700',str(bor_data.parent),str(bor_data))
    # Only the data subtree, including the original mutable signing state, is
    # writable by Heimdall. Configuration and credential links stay root-owned.
    state.command('chown','-R',str(accounts['heimdall']['uid'])+':'+str(accounts['heimdall']['gid']),str(native_home/'data'))
    state.command('chown','0:'+str(accounts['heimdall']['gid']),str(native_home),str(native_home/'config'))
    state.command('chmod','0750',str(native_home),str(native_home/'config'))
    if expected['role']=='validator':
        issuer_dir=state.protected('/etc/polygon/empty-ca',missing=True)
        if not issuer_dir.exists():
            issuer_dir.mkdir(mode=0o755);issuer_dir.chmod(0o755);host.sync_parents(issuer_dir,state.root)
        if not issuer_dir.is_dir() or any(issuer_dir.iterdir()):raise ValueError('ambient native issuers cannot be adopted')
    public_launch=launch.metadata(expected,profile,releases)
    launch_file=state.path('/etc/polygon/launch.json')
    pending=launch_file.with_suffix('.pending');pending.write_bytes(canonical(public_launch));pending.chmod(0o644);host.publish(pending,launch_file,stop=state.root)
    files={'/etc/polygon/launch.json':artifacts.digest(launch_file)}
    for path,text,group in [('/etc/polygon/bor.toml',bor,'polygon-bor'),
            ('/var/lib/polygon/heimdall/config/config.toml',consensus,'polygon-heimdall'),
            ('/var/lib/polygon/heimdall/config/app.toml',app,'polygon-heimdall'),
            ('/var/lib/polygon/heimdall/config/client.toml',configure.client(profile),'polygon-heimdall')]:
        output=state.path(path);pending=output.with_suffix('.pending')
        pending.write_text(text);pending.chmod(0o640)
        state.command('chown','0:'+str(accounts['bor' if group=='polygon-bor' else 'heimdall']['gid']),str(pending));host.publish(pending,output,stop=state.root)
        files[path]=artifacts.digest(output)
    files['/var/lib/polygon/genesis/'+expected['network']+'.json']=profile['heimdall_genesis']['sha256']
    helpers=publish_helpers(state,source_dir)
    for name in SCRIPTS:
        path='/usr/local/lib/erpc/polygon/releases/'+helpers+'/'+name
        files[path]=artifacts.digest(state.path(path))
    state.write('/etc/polygon/installed.json',{'contract':expected,'profile':profile,
        'profile_sha256':profile_digest(profile),'binaries':releases,'files':files,'helpers':helpers})
    return installed(state,expected,require_units=False)


def pending_units(state,expected,receipt):
    """Read-only qualification of stopped, partially published original units.

    Only immutable helper identities already recorded by this preparation or
    its original activation may appear. Nothing here seals units, enables a
    service or repairs an unknown hook; the next explicit deployment publishes
    and seals its own complete units again.
    """
    state.stopped();state.namespaces()
    sources={receipt['helpers']}
    active=state.path('/etc/polygon/activation.json')
    if active.exists():
        value=state.read('/etc/polygon/activation.json')
        if (not isinstance(value,dict) or set(value)!={'contract','profile','helpers','intent','firewall'}
                or value['contract']!=expected or any(not isinstance(value[key],str) or not re.fullmatch('[a-f0-9]{64}',value[key]) for key in ('profile','helpers'))
                or not isinstance(value['intent'],str) or not re.fullmatch('[a-f0-9]{32}',value['intent'])
                or not isinstance(value['firewall'],dict) or set(value['firewall'])!={'run','bundle'}
                or not isinstance(value['firewall']['run'],str) or not re.fullmatch('r-[a-z0-9-]{8,80}',value['firewall']['run'])
                or not isinstance(value['firewall']['bundle'],str) or not re.fullmatch('[a-f0-9]{64}',value['firewall']['bundle'])):
            raise ValueError('previous activation source belongs to another original authority')
        sources.add(value['helpers'])
    prefixes={}
    for digest in sources:
        root='/usr/local/lib/erpc/polygon/releases/'+digest
        directory=state.protected(root)
        if helper_digest(directory)!=digest:raise ValueError('retained original helper source changed')
        path=root+'/control.py';controller=state.protected(path)
        prefixes[digest]=(root,' '.join(shlex.split(service_guard(controller,path))),
                          ' '.join(shlex.split(service_condition(controller,path))))
    original=state.accounts.verify(expected)
    keys=('ExecCondition','ExecStartPre','ExecStart','ExecStartPost','ExecStop','ExecStopPost','ExecReload')
    def tail(value,prefix,token=False,source=None):
        if not value.startswith(prefix+' '):return False
        try:
            text=value[len(prefix)+1:];first,end=json.JSONDecoder(object_pairs_hook=unique).raw_decode(text)
            if first!=expected:return False
            remaining=text[end:].strip()
            if not token:return not remaining
            extra=json.loads(remaining,object_pairs_hook=unique)
            return (set(extra)=={'creation','container_id','helpers'} and extra['helpers']==source
                    and re.fullmatch('[a-f0-9]{32}',extra['creation']) and re.fullmatch('[a-f0-9]{64}',extra['container_id']))
        except (ValueError,TypeError,KeyError):return False
    def allowed(unit,key,text):
        component={'polygon-bor':'bor','polygon-heimdall':'heimdall','polygon-l1-proxy':'parent'}.get(unit)
        for digest,(root,guard,condition) in prefixes.items():
            if component:
                if key=='ExecStart':
                    command=root+'/'+('parent.py '+receipt['profile']['parent'] if component=='parent' else 'launch.py '+component)
                    if text=='/usr/bin/python3 -I '+command:return True
                if key=='ExecCondition' and tail(text,condition+' credential-condition '+component):return True
                if key=='ExecStartPre' and tail(text,guard+' runtime '+component):return True
            elif unit=='polygon-broker':
                modes={'ExecCondition':(condition,'broker-condition'),'ExecStart':(guard,'broker-start'),'ExecStop':(guard,'broker-stop')}
                if key in modes:
                    prefix,mode=modes[key]
                    if tail(text,prefix+' '+mode,token=True,source=digest):return True
            elif unit.startswith('polygon-peer-') and not unit.endswith('.timer'):
                peer_component=unit.removeprefix('polygon-peer-')
                if key=='ExecStart' and tail(text,guard+' peer-publish '+peer_component):return True
        return False
    def expected_keys(unit):
        if unit.endswith('.timer'):return set()
        if unit=='polygon-broker':return {'ExecCondition','ExecStart','ExecStop'}
        if unit.startswith('polygon-peer-'):return {'ExecStart'}
        return {'ExecCondition','ExecStartPre','ExecStart'}
    for unit in sorted(unit_names(expected)):
        name=unit+('' if unit.endswith('.timer') else '.service');path=state.protected(unit_path(unit),missing=True)
        def show(key):return state.command('systemctl','show','--property='+key,'--value',name).stdout.decode().strip()
        loaded=show('LoadState')
        if loaded not in ('loaded','not-found'):raise ValueError('unfinished unit load authority is unknown')
        if not path.exists():
            if loaded!='not-found':raise ValueError('cached unit without its original file requires explicit recovery')
            continue
        if path.stat().st_size>262144:raise ValueError('unfinished service definition exceeds its bound')
        lines=path.read_text().splitlines();commands={key:[] for key in keys}
        for line in lines:
            if line.startswith('Exec') and '=' in line:
                key,value=line.split('=',1)
                if key not in commands:raise ValueError('unknown service execution hook')
                parsed=shlex.split(value)
                if parsed and parsed[0].startswith('+'):parsed[0]=parsed[0][1:]
                text=' '.join(parsed)
                if not allowed(unit,key,text):raise ValueError('unfinished '+unit+' '+key+' selects an unknown original execution hook')
                commands[key].append(text)
        required=expected_keys(unit)
        if any(len(commands[key])!=(1 if key in required else 0) for key in keys):
            raise ValueError('unfinished unit has missing or extra execution hooks')
        if unit.endswith('.timer'):
            required_timer=('OnBootSec=15s','OnUnitActiveSec=15s','AccuracySec=1s','Persistent=false','Unit='+unit.removesuffix('.timer')+'.service')
            if any(lines.count(setting)!=1 for setting in required_timer) or any(line.startswith('On') and '=' in line and line not in required_timer for line in lines):
                raise ValueError('unfinished peer timer has an unknown trigger or recipient')
        if not unit.endswith('.timer'):
            component={'polygon-bor':'bor','polygon-heimdall':'heimdall','polygon-l1-proxy':'parent'}.get(unit)
            uid=str(original[component]['uid']) if component else '0'
            gid=str(original[component or 'broker']['gid']) if component or unit=='polygon-broker' else '0'
            if lines.count('User='+uid)!=1 or lines.count('Group='+gid)!=1:
                raise ValueError('unfinished unit recipient differs from original numeric authority')
        drop=state.protected(unit_path(unit)+'.d',missing=True);guard=None
        if drop.exists():
            if {p.name for p in drop.iterdir()}-{'50-erpc-firewall-guard.conf','50-erpc-firewall-guard.conf.new'}:
                raise ValueError('unknown unfinished service override')
            file=drop/'50-erpc-firewall-guard.conf'
            if file.exists():
                expected_guard=state.firewall().guard_config()
                if file.read_text()!=expected_guard:raise ValueError('unfinished common firewall hook changed')
                guard=' '.join(shlex.split(next(line.split('=',1)[1].removeprefix('+') for line in expected_guard.splitlines() if line.startswith('ExecStartPre='))))
        if loaded=='not-found':continue
        if show('FragmentPath')!=unit_path(unit):raise ValueError('loaded service fragment differs from original unit path')
        overrides=shlex.split(show('DropInPaths'))
        wanted=[unit_path(unit)+'.d/50-erpc-firewall-guard.conf'] if guard else []
        if overrides!=wanted:raise ValueError('unknown loaded service override')
        if unit.endswith('.timer') and show('Unit')!=unit.removesuffix('.timer')+'.service':raise ValueError('loaded peer timer points to another service')
        if not unit.endswith('.timer') and (show('User')!=uid or show('Group')!=gid or show('DynamicUser')!='no' or show('SupplementaryGroups')!=''):
            raise ValueError('loaded original credential recipient changed')
        for key in keys:
            value=show(key)
            pattern=r'\{ path=([^;]+) ; argv\[\]=(.*?) ; ignore_errors=(no|yes) ;[^}]*\}'
            parsed=re.findall(pattern,value,re.S)
            remaining=re.sub(pattern,'',value,flags=re.S).strip(' ;\n\t')
            if value and (not parsed or remaining or any(ignore!='no' or executable.strip()!=args.split(' ',1)[0] for executable,args,ignore in parsed)):
                raise ValueError('unreadable, substituted or ignored loaded execution hook')
            values=[args for _,args,_ in parsed]
            common=guard is not None and key=='ExecStartPre'
            if len(values)!=(1 if key in required else 0)+(1 if common else 0):
                raise ValueError('loaded service has missing or extra execution hooks')
            for args in values:
                if common and args==guard:continue
                if not allowed(unit,key,args):raise ValueError('unknown loaded original execution hook')
            if common and values.count(guard)!=1:raise ValueError('loaded firewall guard differs')
    state.stopped()
    return {'unsealed_original_units_verified':True}

# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Closed RabbitMQ 4.4 protocol configuration for the native Heimdall bridge.

The native machinery result cache declares transient non-exclusive queues.
Only that compatibility feature is permitted in this dedicated broker. These
pins do not authorize automatic native version changes or database downgrades.
"""
import re

VERSION='4.4.0'
SOURCE='24d5157cd415ef396c8ecd40a2d08c4d7ad3da9f'
RECIPE='4ad287295317ea1d9a577396fa28466a1bbf3430'
INDEX='sha256:485319d42170eab53d8a030e1cc49d95e41f5d325479fa504736db8091981eb7'
IMAGES={
    'x86_64':{'platform':'linux/amd64',
        'manifest':'sha256:184d4ae2a5d7fd4cbe1ad7165d1fb6c1377735ed2744c6be478deed5e8f0ba88',
        'config':'sha256:f145e7a82c858bcb253703571f5dce9ca48854358a68025c638e3fb5a4318969'},
    'aarch64':{'platform':'linux/arm64',
        'manifest':'sha256:ee92d0416effc808debd1f2c009ca3ebce48d6aa9a60dc1b0063bd66d876ec81',
        'config':'sha256:2aba0be223bfd021ffb3f6a961ee416df5df03e78d1c5efc25fb285c56196679'},
}
NAME='erpc-polygon-broker'
DATA='/var/lib/polygon/broker'
RUNTIME='/run/erpc-polygon-broker'
USER='heimdall'
VHOST='polygon'


def require(value,message):
    if not value:raise ValueError(message)


def image(architecture):
    require(architecture in IMAGES,'broker architecture has no reviewed immutable image')
    return 'docker.io/library/rabbitmq@'+IMAGES[architecture]['manifest']


def identity(expected):
    require(expected.get('role')=='validator','broker is exclusive to admitted validator operations')
    return {'version':VERSION,'source':SOURCE,'recipe':RECIPE,'index':INDEX,
        'image':image(expected['architecture']),**IMAGES[expected['architecture']]}


def transition(expected,previous):
    wanted=identity(expected)
    require(previous is None or previous==wanted,
            'broker native release change requires an explicit reviewed upgrade catalog')
    return wanted


def credential(value,expected):
    require(isinstance(value,dict) and set(value)=={'format','contract','password','cookie'}
            and type(value['format']) is int and value['format']==1 and value['contract']==expected
            and expected.get('role')=='validator'
            and all(isinstance(value[name],str) and re.fullmatch('[a-f0-9]{64}',value[name]) for name in ('password','cookie'))
            and value['password']!=value['cookie'],'broker original credential is invalid')
    return value


def configuration(value,expected):
    credential(value,expected)
    # This file is generated only in root-managed tmpfs, readable by the
    # original broker UID. It is never public inventory, argv or environment.
    return '\n'.join([
        'listeners.tcp = none','listeners.ssl.1 = 127.0.0.14:5671',
        'ssl_options.cacertfile = /etc/rabbitmq/ca.pem',
        'ssl_options.certfile = /etc/rabbitmq/certificate.pem',
        'ssl_options.keyfile = /etc/rabbitmq/private-key.pem',
        'ssl_options.verify = verify_none','ssl_options.fail_if_no_peer_cert = false',
        'ssl_options.versions.1 = tlsv1.3','ssl_options.versions.2 = tlsv1.2',
        'default_user = '+USER,'default_pass = '+value['password'],'default_vhost = '+VHOST,
        'default_user_tags.administrator = false','loopback_users.'+USER+' = true',
        'default_permissions.configure = .*','default_permissions.read = .*','default_permissions.write = .*',
        'distribution.listener.interface = 127.0.0.1',
        'distribution.listener.port_range.min = 25672','distribution.listener.port_range.max = 25672',
        'log.console = true','log.console.level = warning','log.file = false',
        'deprecated_features.permit.transient_nonexcl_queues = true',''])


def native_url(value,expected):
    credential(value,expected)
    return 'amqps://'+USER+':'+value['password']+'@127.0.0.14:5671/'+VHOST


def arguments(expected,account,helpers,creation):
    wanted=identity(expected)
    require(set(account)=={'uid','gid'} and all(type(value) is int and 100<=value<=999 for value in account.values())
            and re.fullmatch('[a-f0-9]{64}',helpers or '') is not None
            and re.fullmatch('[a-f0-9]{32}',creation or '') is not None,
            'broker launch requires original numeric account and reviewed helpers')
    return ['/usr/bin/docker','run','--name',NAME,'--pull=never','--read-only',
        '--network=host','--cgroupns=private','--cgroup-parent=system.slice','--ipc=private','--user',str(account['uid'])+':'+str(account['gid']),
        '--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=256','--memory=4g','--memory-swap=4g','--cpus=4',
        '--ulimit','core=0:0','--ulimit','nofile=65536:65536',
        '--stop-timeout=120','--log-driver=none','--restart=no',
        '--label','erpc.polygon.owner='+expected['owner'],'--label','erpc.polygon.helpers='+helpers,
        '--label','erpc.polygon.creation='+creation,
        '--mount','type=bind,src='+DATA+',dst=/var/lib/rabbitmq',
        '--mount','type=bind,src='+RUNTIME+'/config,dst=/etc/rabbitmq,readonly',
        '--mount','type=bind,src='+RUNTIME+'/cookie,dst=/var/lib/rabbitmq/.erlang.cookie,readonly',
        '--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=1777',
        '--env','HOME=/var/lib/rabbitmq','--env','RABBITMQ_NODENAME=polygon@localhost',
        '--env','RABBITMQ_USE_LONGNAME=false','--env','ERL_EPMD_ADDRESS=127.0.0.1',
        '--env','RABBITMQ_CONF_ENV_FILE=/etc/rabbitmq/rabbitmq-env.conf',
        '--env','RABBITMQ_CONFIG_FILE=/etc/rabbitmq/rabbitmq',
        '--env','RABBITMQ_ENABLED_PLUGINS_FILE=/etc/rabbitmq/enabled_plugins',
        '--env','RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS=+S 4:4 +A 8',
        '--platform',wanted['platform'],wanted['image'],'rabbitmq-server']


def environment(values):
    require(isinstance(values,list) and all(isinstance(value,str) and '=' in value for value in values),
            'broker image environment is malformed')
    pairs=[value.split('=',1) for value in values]
    require(len({key for key,_ in pairs})==len(pairs),'broker environment repeats a variable')
    return dict(pairs)


def image_info(value,expected):
    """Validate the root daemon's immutable config identity before publication."""
    wanted=identity(expected)
    require(isinstance(value,dict) and value.get('Id')==wanted['config']
            and value.get('Os')=='linux' and value.get('Architecture')==wanted['platform'].split('/')[1],
            'broker image differs from the reviewed native architecture/config digest')
    names={'rabbitmq@'+wanted['manifest'],'library/rabbitmq@'+wanted['manifest'],wanted['image']}
    require(isinstance(value.get('RepoDigests'),list) and bool(names.intersection(value['RepoDigests'])),
            'broker image has no original official repository manifest')
    config=value.get('Config')
    require(isinstance(config,dict) and config.get('Entrypoint')==['docker-entrypoint.sh']
            and config.get('Cmd')==['rabbitmq-server'] and config.get('Healthcheck') in (None,{})
            and environment(config.get('Env')).get('RABBITMQ_VERSION')==VERSION,
            'broker image native version or entrypoint differs')
    return config


def prepare_image(state,expected,intent,profile,helpers):
    import broker_docker
    import broker_storage
    state.phase(expected,intent,profile,helpers);state.stopped()
    account=state.accounts.verify(expected)['broker']
    broker_storage.original(state,expected,account)
    previous=None;record='/etc/polygon/broker-image.json'
    if state.path(record).exists():
        saved=state.read(record)
        require(set(saved)=={'contract','image'} and saved['contract']==expected,'broker image belongs to another inventory')
        previous=saved['image']
    wanted=transition(expected,previous)
    client=broker_docker.Docker(state,expected,create=True)
    existing=client.call('image','inspect',wanted['image'],check=False,timeout=30)
    if existing.returncode:
        client.call('image','pull','--platform',wanted['platform'],wanted['image'],timeout=1800)
        observed=client.inspect('image',wanted['image'])
    else:
        rows=broker_docker.decode(existing.stdout)
        require(isinstance(rows,list) and len(rows)==1,'broker image inspection is ambiguous')
        observed=rows[0]
    image_info(observed,expected)
    state.phase(expected,intent,profile,helpers);state.stopped();broker_storage.original(state,expected,account)
    state.write(record,{'contract':expected,'image':wanted})
    return wanted


def container_info(value,expected,account,helpers,original_image,creation,container_id=None,stopping=False):
    """Refuse adopting a name/label match with different runtime authority."""
    config=image_info(original_image,expected);wanted=identity(expected)
    require(isinstance(value,dict) and re.fullmatch('[a-f0-9]{64}',value.get('Id','')) is not None
            and (container_id is None or value['Id']==container_id) and value.get('Name')=='/'+NAME
            and value.get('Image')==wanted['config'],'broker container identity changed')
    actual=value.get('Config');host=value.get('HostConfig')
    require(isinstance(actual,dict) and isinstance(host,dict),'broker container metadata is incomplete')
    args=arguments(expected,account,helpers,creation)
    overrides=[args[index+1] for index,argument in enumerate(args[:-1]) if argument=='--env']
    env=dict(environment(config['Env']),**environment(overrides))
    labels=dict(config.get('Labels') or {},**{'erpc.polygon.owner':expected['owner'],'erpc.polygon.helpers':helpers,'erpc.polygon.creation':creation})
    require(actual.get('Image')==wanted['image'] and actual.get('User')==str(account['uid'])+':'+str(account['gid'])
            and actual.get('Entrypoint')==config['Entrypoint'] and actual.get('Cmd')==config['Cmd']
            and actual.get('Labels')==labels and environment(actual.get('Env'))==env
            and actual.get('Healthcheck') in (None,{}) and actual.get('StopTimeout')==120,
            'broker container command, original account, environment or labels changed')
    require(host.get('ReadonlyRootfs') is True and host.get('Privileged') is False
            and host.get('NetworkMode')=='host' and host.get('CgroupnsMode')=='private' and host.get('CgroupParent')=='system.slice'
            and host.get('PidMode')=='' and host.get('UTSMode')=='' and host.get('UsernsMode')==''
            and host.get('IpcMode')=='private' and host.get('CapDrop')==['ALL']
            and host.get('SecurityOpt') in (['no-new-privileges'],['no-new-privileges:true'])
            and host.get('RestartPolicy')=={'Name':'no','MaximumRetryCount':0}
            and host.get('AutoRemove') is False and host.get('Init') in (None,False)
            and host.get('LogConfig')=={'Type':'none','Config':{}},'broker container isolation changed')
    for name in ('CapAdd','GroupAdd','Devices','DeviceRequests','VolumesFrom','Links','Binds','PortBindings','Sysctls'):
        require(host.get(name) in (None,[],{}),'broker container gained additional host authority')
    require(host.get('Tmpfs')=={'/tmp':'rw,noexec,nosuid,nodev,size=67108864,mode=1777'},
            'broker temporary storage differs')
    if not stopping:
        require(host.get('PidsLimit')==256 and host.get('Memory')==4*1024**3
                and host.get('MemorySwap')==4*1024**3 and host.get('NanoCpus')==4*10**9,
                'broker runtime resource budget differs')
    limits=host.get('Ulimits')
    require(isinstance(limits,list) and len(limits)==2
            and all(isinstance(value,dict) and set(value)=={'Name','Soft','Hard'} for value in limits)
            and sorted(limits,key=lambda value:value['Name'])==[
                {'Name':'core','Soft':0,'Hard':0},{'Name':'nofile','Soft':65536,'Hard':65536}],
            'broker core or file-descriptor limits changed')
    mounts=value.get('Mounts');require(isinstance(mounts,list),'broker mount metadata is unavailable')
    expected_mounts={'/var/lib/rabbitmq':(DATA,True),'/etc/rabbitmq':(RUNTIME+'/config',False),
        '/var/lib/rabbitmq/.erlang.cookie':(RUNTIME+'/cookie',False)}
    seen=set()
    for mount in mounts:
        destination=mount.get('Destination')
        if mount.get('Type')=='tmpfs' and destination=='/tmp':continue
        require(destination in expected_mounts and destination not in seen and mount.get('Type')=='bind',
                'broker has an unexpected or repeated mount')
        source,writable=expected_mounts[destination]
        require(mount.get('Source')==source and mount.get('RW') is writable
                and mount.get('Propagation')=='rprivate','broker mount source or write access changed')
        seen.add(destination)
    require(seen==set(expected_mounts),'broker original storage/configuration mounts are incomplete')
    return value['Id']

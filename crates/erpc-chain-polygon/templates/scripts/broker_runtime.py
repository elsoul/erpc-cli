# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original broker custody and private, numeric-recipient runtime publication."""
import hashlib
import json
import os
import stat
import broker
import host
import local_tls
from state import canonical,unique

CIPHER='/etc/credstore.encrypted/polygon/broker-original'
RECORD='/etc/polygon/broker-custody.json'
NAME='polygon-broker-original'


def require(value,message):
    if not value:raise ValueError(message)


def generate(expected):
    import secrets
    return {'format':1,'contract':expected,'password':secrets.token_hex(32),'cookie':secrets.token_hex(32)}


def original(state,expected,convert=None):
    state.ownership(expected)
    convert=convert or (lambda action,name,raw:local_tls.transform(state,action,name,raw))
    cipher=state.protected(CIPHER).read_bytes()
    require(0<len(cipher)<=65536,'broker original ciphertext exceeds its bound')
    receipt={'contract':expected,'cipher_sha256':hashlib.sha256(cipher).hexdigest()}
    require(state.read(RECORD)==receipt,'broker original ciphertext or ownership changed')
    value=json.loads(convert('decrypt',NAME,cipher),object_pairs_hook=unique)
    return broker.credential(value,expected)


def prepare(state,expected,intent,profile,helpers,create=None,convert=None):
    state.phase(expected,intent,profile,helpers);state.stopped();state.accounts.verify(expected)
    require(expected.get('role')=='validator' and state.path('/etc/polygon/preparing').exists(),
            'broker credentials require a stopped validator preparation')
    convert=convert or (lambda action,name,raw:local_tls.transform(state,action,name,raw))
    path=state.protected(CIPHER,missing=True);pending=state.protected(CIPHER+'.pending',missing=True)
    require(path.exists() or pending.exists() or not state.path(RECORD).exists(),
            'original broker credential is missing; explicit recovery required')
    require(not(path.exists() and pending.exists()),'conflicting broker credential staging requires recovery')
    if not path.exists():
        if not pending.exists():
            value=broker.credential((create or generate)(expected),expected)
            local_tls.write_bytes(state,CIPHER+'.pending',convert('encrypt',NAME,canonical(value)))
        cipher=pending.read_bytes()
        require(0<len(cipher)<=65536,'broker original ciphertext exceeds its bound')
        broker.credential(json.loads(convert('decrypt',NAME,cipher),object_pairs_hook=unique),expected)
        state.phase(expected,intent,profile,helpers);state.stopped()
        host.publish(pending,path,stop=state.root)
    cipher=path.read_bytes()
    require(0<len(cipher)<=65536,'broker original ciphertext exceeds its bound')
    broker.credential(json.loads(convert('decrypt',NAME,cipher),object_pairs_hook=unique),expected)
    receipt={'contract':expected,'cipher_sha256':hashlib.sha256(cipher).hexdigest()}
    if state.path(RECORD).exists():require(state.read(RECORD)==receipt,'original broker credentials changed')
    state.phase(expected,intent,profile,helpers);state.stopped();state.write(RECORD,receipt)
    return original(state,expected,convert)


def directory(state,name,gid):
    path=state.protected(name,missing=True)
    if not path.exists():path.mkdir(mode=0o700)
    before=path.lstat()
    if stat.S_ISDIR(before.st_mode) and before.st_uid==state.owner and stat.S_IMODE(before.st_mode)==0o700 and not any(path.iterdir()):
        # A crash between mkdir and numeric handoff leaves a root-private empty
        # staging directory. No native history or existing private file is adopted.
        descriptor=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            opened=os.fstat(descriptor)
            require((opened.st_dev,opened.st_ino)==(before.st_dev,before.st_ino),'runtime directory changed before handoff')
            os.fchown(descriptor,state.owner,gid);os.fchmod(descriptor,0o750);os.fsync(descriptor)
        finally:os.close(descriptor)
        host.sync_parents(path,state.root)
    info=path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==state.owner and info.st_gid==gid
            and stat.S_IMODE(info.st_mode)==0o750,'broker runtime directory differs from the original numeric recipient')
    return path


def private_file(state,path,raw,uid,gid,mode):
    """Never truncate a native-owned file or follow its link as root."""
    require(isinstance(raw,bytes) and 0<len(raw)<=65536,'broker private file exceeds its bound')
    for current in (path,path.with_name(path.name+'.pending')):
        if current.exists() or current.is_symlink():
            info=current.lstat()
            interrupted=current!=path and stat.S_IMODE(info.st_mode)==0o600
            require(stat.S_ISREG(info.st_mode) and info.st_nlink==1
                    and info.st_uid in (state.owner,uid)
                    and (info.st_gid==gid or interrupted and info.st_uid==state.owner)
                    and (stat.S_IMODE(info.st_mode)==mode or interrupted),
                    'unsafe existing broker runtime file cannot be adopted')
    pending=path.with_name(path.name+'.pending')
    if pending.exists():host.unlink(pending,state.root)
    descriptor=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(descriptor,'wb') as output:
        output.write(raw);output.flush();os.fchown(output.fileno(),uid,gid)
        os.fchmod(output.fileno(),mode);os.fsync(output.fileno())
    # Preserve the stopped fence and exact pending file on publication failure.
    host.publish(pending,path,stop=state.root)


def stage(state,expected,intent,profile,helpers,convert=None,validator=local_tls.validate,authorize=None):
    """Root-only caller; private leaf/cookie are handed to original IDs only."""
    def guard():
        if authorize is None:state.phase(expected,intent,profile,helpers);state.stopped()
        else:authorize()
    guard()
    account=state.accounts.verify(expected)['broker']
    value=original(state,expected,convert)
    tls,_receipt=local_tls.load(state,expected,convert=convert,validator=validator)
    mount=state.command('findmnt','--noheadings','--raw','--output','TARGET,FSTYPE','--target','/run',timeout=15).stdout.decode().strip()
    require(mount.split()==['/run','tmpfs'],'broker private runtime requires the host tmpfs')
    state.protected('/run')
    root=directory(state,broker.RUNTIME,account['gid'])
    actual=state.command('findmnt','--noheadings','--raw','--output','TARGET,FSTYPE','--target',broker.RUNTIME,timeout=15).stdout.decode().split()
    require(actual==['/run','tmpfs'],'broker private runtime cannot use a substituted nested mount')
    require({path.name for path in root.iterdir()}<={'config','cookie','cookie.pending'},
            'unknown broker runtime contents cannot be adopted')
    config=directory(state,broker.RUNTIME+'/config',account['gid'])
    contents={'rabbitmq.conf':broker.configuration(value,expected).encode(),
        'rabbitmq-env.conf':b'RUNNING_UNDER_SYSTEMD=true\n',
        # The official image otherwise enables a public Prometheus listener.
        'enabled_plugins':b'[].\n','ca.pem':tls['ca'].encode(),
        'certificate.pem':tls['leaves']['broker']['certificate'].encode(),
        'private-key.pem':tls['leaves']['broker']['key'].encode()}
    require({path.name for path in config.iterdir()}<=set(contents)|{name+'.pending' for name in contents},
            'unknown broker configuration cannot be adopted')
    for name,raw in contents.items():private_file(state,config/name,raw,state.owner,account['gid'],0o440)
    private_file(state,root/'cookie',value['cookie'].encode(),account['uid'],account['gid'],0o400)
    guard();state.accounts.verify(expected)
    return {'contract':expected,'account':account,'ca_sha256':hashlib.sha256(tls['ca'].encode()).hexdigest()}


CONTAINER='/etc/polygon/broker-container.json'


def quiet(state,record):
    """Docker stopped is insufficient: retained UID/data writers must drain."""
    proof=state.proof
    processes=[int(path.name) for path in proof.proc.iterdir() if path.name.isdecimal()]
    require(bool(processes),'Linux process table is unavailable for original broker drain')
    prefixes=(broker.DATA,str(state.path(broker.DATA)),broker.RUNTIME,str(state.path(broker.RUNTIME)))
    for pid in processes:
        try:value=proof.process(pid)
        except FileNotFoundError:
            require(not(proof.proc/str(pid)).exists(),'live broker process metadata became unavailable')
            continue
        if value['dead']:continue
        paths=[os.fsdecode(item) for item in value['arguments']]+value['descriptors']
        require(record['account']['uid'] not in value['uids']
                and not any(prefix in path for prefix in prefixes for path in paths)
                and record['container_id'] not in value['cgroup'],
                'original broker UID, container cgroup or data writer remains; explicit recovery required')


def container_record(state,expected):
    import re
    record=state.read(CONTAINER)
    require(isinstance(record,dict) and set(record)=={'format','contract','account','helpers','image','creation','container_id','state'}
            and type(record['format']) is int and record['format']==1 and record['contract']==expected
            and record['image']==broker.identity(expected)
            and isinstance(record['creation'],str) and re.fullmatch('[a-f0-9]{32}',record['creation'])
            and record['state'] in ('reserved','created','retiring','retired')
            and (record['container_id'] is None and record['state']=='reserved'
                 or isinstance(record['container_id'],str) and re.fullmatch('[a-f0-9]{64}',record['container_id'])),
            'original broker container receipt is incomplete or belongs to another authority')
    broker.arguments(expected,record['account'],record['helpers'],record['creation'])
    return record

class Container:
    """One immutable creation token per CID; delayed callbacks never select by name."""
    def __init__(self,state,expected,client=None):
        import broker_docker
        state.ownership(expected);state.namespaces()
        self.state,self.expected=state,expected
        self.client=client or broker_docker.Docker(state,expected)

    def record(self):return container_record(self.state,self.expected)

    def lookup(self,identity):
        import re
        require(identity==broker.NAME or re.fullmatch('[a-f0-9]{64}',identity or ''),'unknown broker container selector')
        selector='name=^/'+broker.NAME+'$' if identity==broker.NAME else 'id='+identity
        raw=self.client.call('container','ls','--all','--no-trunc','--filter',selector,'--format','{{.ID}}',timeout=30).stdout
        require(isinstance(raw,bytes) and len(raw)<=4096,'broker lookup exceeds its public bound')
        rows=raw.decode().splitlines()
        require(len(rows)<=1 and all(re.fullmatch('[a-f0-9]{64}',row) for row in rows),'broker container lookup is ambiguous')
        if not rows:return None
        require(identity==broker.NAME or rows[0]==identity,'broker lookup selected another original CID')
        return self.client.inspect('container',rows[0])

    def verify(self,value,record,stopping=False):
        image=self.client.inspect('image',record['image']['image'])
        return broker.container_info(value,self.expected,record['account'],record['helpers'],image,
            record['creation'],record['container_id'],stopping=stopping)

    @staticmethod
    def stopped(value):
        status=value.get('State')
        require(isinstance(status,dict) and status.get('Running') is False and status.get('Paused') is False
                and status.get('Restarting') is False and status.get('Dead') is False
                and type(status.get('Pid')) is int and status['Pid']==0 and status.get('Status') in ('created','exited'),
                'original broker container has not finished draining')

    @staticmethod
    def token(record):
        require(record['state']=='created','broker callback requires a fully published original CID')
        return {key:record[key] for key in ('creation','container_id','helpers')}

    def bound(self,token):
        record=self.record()
        require(isinstance(token,dict) and token==self.token(record),
                'delayed broker operation does not belong to the current original container')
        return record

    def retire(self,record):
        """Caller holds the global operation lock and has drained every node."""
        require(self.record()==record and record['state'] in ('created','retiring'),
                'broker retirement differs from its original publication')
        value=self.lookup(record['container_id'])
        if value is not None:self.verify(value,record,stopping=True);self.stopped(value)
        else:require(record['state']=='retiring','missing original broker container cannot be implicitly replaced')
        quiet(self.state,record)
        record=dict(record,state='retiring');self.state.write(CONTAINER,record)
        if value is not None:self.client.call('container','rm',record['container_id'],timeout=60)
        require(self.lookup(record['container_id']) is None,'retired broker CID still exists')
        quiet(self.state,record)
        record=dict(record,state='retired');self.state.write(CONTAINER,record)
        return record

    def prepare(self,intent,profile,helpers,creation=None,stage_files=stage):
        import broker_storage
        import uuid
        state,expected=self.state,self.expected
        state.phase(expected,intent,profile,helpers);state.stopped()
        account=state.accounts.verify(expected)['broker'];broker_storage.original(state,expected,account)
        wanted=broker.identity(expected)
        require(state.read('/etc/polygon/broker-image.json')=={'contract':expected,'image':wanted},
                'broker image was not prepared for the original validator')
        broker.image_info(self.client.inspect('image',wanted['image']),expected)
        record=self.record() if state.path(CONTAINER).exists() else None
        if record is not None:
            require(record['account']==account,'broker original numeric recipient changed')
            if record['state']=='retiring' or record['state']=='created' and record['helpers']!=helpers:
                record=self.retire(record)
            if record['state']=='reserved':
                require(record['helpers']==helpers,'unfinished broker creation requires its original helper revision')
        if record is None or record['state']=='retired':
            require(self.lookup(broker.NAME) is None,'unknown existing broker container name cannot be adopted')
            record={'format':1,'contract':expected,'account':account,'helpers':helpers,'image':wanted,
                'creation':creation or uuid.uuid4().hex,'container_id':None,'state':'reserved'}
            broker.arguments(expected,account,helpers,record['creation'])
            state.write(CONTAINER,record)  # Durable intent before Docker can create anything.
        if record['state']=='created':
            value=self.lookup(record['container_id'])
            require(value is not None,'original broker CID is missing; explicit recovery required')
        else:
            value=self.lookup(broker.NAME)
            # Repeat durable publication on recovery from an uncertain fsync.
            state.write(CONTAINER,record)
        if value is not None:
            self.verify(value,record);self.stopped(value)
        # A foreign/replaced container must be refused BEFORE private files are
        # refreshed in paths that its old mount could otherwise still read.
        stage_files(state,expected,intent,profile,helpers)
        state.phase(expected,intent,profile,helpers);state.stopped()
        if value is None:
            args=broker.arguments(expected,account,helpers,record['creation']);args[1]='create'
            # On timeout/error keep the exact reservation. A retry inspects
            # that original creation label; it never invents another ID.
            self.client.call(*args[1:],timeout=120)
            value=self.lookup(broker.NAME)
            require(value is not None,'broker creation has no observable original CID')
        cid=self.verify(value,record);self.stopped(value)
        state.phase(expected,intent,profile,helpers);state.stopped()
        record=dict(record,container_id=cid,state='created');state.write(CONTAINER,record)
        return self.token(record)

    def start_command(self,token):
        import broker_storage
        record=self.bound(token)
        require(self.state.accounts.verify(self.expected)['broker']==record['account'],
                'broker startup recipient differs from its original account')
        broker_storage.original(self.state,self.expected,record['account'])
        value=self.lookup(record['container_id'])
        require(value is not None,'original broker CID is missing')
        self.verify(value,record);self.stopped(value);quiet(self.state,record)
        require(not any(row[0] in (4369,5671,25672) for row in self.state.proof.listening()),
                'an unowned listener occupies a dedicated broker port')
        # Root service launcher executes this fixed argv after its current
        # activation/firewall check and private-file staging. No name lookup.
        return [*self.client.prefix,'container','start','--attach',record['container_id']]

    def health(self,token,connect=None):
        import broker_storage
        import re
        import socket
        record=self.bound(token)
        require(self.state.accounts.verify(self.expected)['broker']==record['account'],
                'broker health recipient differs from its original account')
        broker_storage.original(self.state,self.expected,record['account'])
        value=self.lookup(record['container_id']);require(value is not None,'original broker CID is missing')
        self.verify(value,record)
        status=value.get('State',{});pid=status.get('Pid')
        require(status.get('Running') is True and status.get('Status')=='running'
                and status.get('Paused') is False and status.get('Restarting') is False and status.get('Dead') is False
                and type(pid) is int and pid>0,'original broker native process is not running')
        process=self.state.proof.process(pid);uid,gid=record['account']['uid'],record['account']['gid']
        group='/system.slice/docker-'+record['container_id']+'.scope'
        require(not process['dead'] and process['uids']==(uid,)*4 and process['gids']==(gid,)*4
                and set(process['groups'])<={gid} and process['cgroup'].splitlines()==['0::'+group]
                and not process['deleted'] and re.fullmatch(r'/opt/erlang/lib/erlang/erts-[0-9.]+/bin/beam[.]smp',process['executable']),
                'broker listener is not the original image native PID and account')
        path=self.state.path('/proc/'+str(pid))
        active=(path/'exe').stat();original=(path/'root'/process['executable'].lstrip('/')).stat()
        require((active.st_dev,active.st_ino)==(original.st_dev,original.st_ino),
                'broker native executable differs from its read-only image')
        cgroup=self.state.protected('/sys/fs/cgroup'+group)
        require(not cgroup.is_symlink() and str(pid) in (cgroup/'cgroup.procs').read_text().split(),
                'broker native PID escaped its original container cgroup')
        listeners=[row for row in self.state.proof.listening() if row[0]==5671]
        require(bool(listeners) and all(row[1]=='127.0.0.14' and row[2]==uid
                and 'socket:['+row[3]+']' in process['descriptors'] for row in listeners),
                'broker AMQPS listener has another process or address')
        ca=self.state.protected('/etc/polygon/local-ca.pem').read_bytes()
        saved=self.state.read(local_tls.RECORD)
        require(saved.get('contract')==self.expected and hashlib.sha256(ca).hexdigest()==saved.get('ca_sha256'),
                'broker TLS observer has no original issuer')
        context=local_tls.client_context(ca.decode())
        stream=(connect or socket.create_connection)(('127.0.0.14',5671),timeout=8)
        try:
            with context.wrap_socket(stream,server_hostname='127.0.0.14'):pass
        finally:stream.close()
        after=self.lookup(record['container_id'])
        require(after is not None and after.get('State')==status
                and self.state.proof.generation(pid)==process['generation'],
                'broker native process changed during authenticated observation')
        self.verify(after,record);require(self.bound(token)==record,'broker generation changed during health observation')
        again=self.state.proof.process(pid)
        require(all(again.get(key)==process.get(key) for key in
            ('generation','uids','gids','groups','executable','deleted','arguments','cgroup')),
            'broker native identity changed during its TLS observation')
        # Re-read ownership of the same native sockets after the handshake.
        require([row for row in self.state.proof.listening() if row[0]==5671]==listeners,
                'broker listener changed during its TLS observation')
        return {'ready':True,'container_id':record['container_id'],'pid':pid,'generation':process['generation']}

    def stop(self,token):
        record=self.bound(token)  # No NSS/volume dependency; retain original IDs.
        value=self.lookup(record['container_id'])
        require(value is not None,'original broker CID is unavailable for owned shutdown')
        self.verify(value,record,stopping=True)
        self.client.call('container','stop','--time','120',record['container_id'],timeout=150)
        value=self.lookup(record['container_id'])
        require(value is not None,'broker CID disappeared during shutdown')
        self.verify(value,record,stopping=True);self.stopped(value);quiet(self.state,record)
        return {'broker_stopped':True,'container_id':record['container_id']}

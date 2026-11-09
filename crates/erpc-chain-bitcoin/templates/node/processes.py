# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original Bitcoin process/socket proof and retained generation-bound shutdown.

Adapted from this author's reviewed Arc process authority. Kernel device numbers
are only current-observation identifiers; none become persistent volume IDs.
"""
import hashlib
import base64
import http.client
import os
from pathlib import Path
import signal
import shlex
import stat
import time

PROC = Path('/proc')
IMAGE_CACHE = {}
SERVICE_FIELDS = {'LoadState','ActiveState','SubState','MainPID','ControlGroup','FragmentPath','User','Group','DropInPaths',
                  'ExecStart','ExecStartPre','ExecStartPost','ExecStop','ExecStopPost','ExecCondition','NoNewPrivileges'}
LEGACY_UNIT_SHA256 = '2d786096d3f55ee0aecbe0ba965273db89e9c1f25e0aa0ea17d79aa5d92690bd'


def image_hash(path):
    with path.open('rb') as stream:
        before=os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 256*1024*1024,
                'native image is not a bounded regular file')
        key=tuple(getattr(before,name) for name in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns'))
        digest=IMAGE_CACHE.get(key)
        if digest is None:
            calculated=hashlib.sha256()
            for raw in iter(lambda:stream.read(1024*1024),b''):calculated.update(raw)
            digest=calculated.hexdigest()
        after=os.fstat(stream.fileno())
        require(key==tuple(getattr(after,name) for name in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')),
                'native image changed during observation')
        IMAGE_CACHE[key]=digest
    return digest


def process_text(path, maximum=65536):
    with path.open('rb') as stream:raw=stream.read(maximum+1)
    require(len(raw)<=maximum, 'process observation exceeds its bound')
    return raw.decode('utf-8','strict')


def process_record(pid, releases):
    require(type(pid) is int and pid>1, 'invalid original process identifier')
    root=PROC/str(pid)
    before=process_text(root/'stat').rsplit(')',1)[1].split()[19]
    fields={}
    for line in process_text(root/'status').splitlines():
        if ':' in line:
            key,_,value=line.partition(':');fields[key]=value.split()
    require({'Uid','Gid','Groups'}<=set(fields), 'process credentials are unavailable')
    executable=os.readlink(root/'exe')
    deleted=executable.endswith(' (deleted)')
    if deleted:executable=executable[:-10]
    paths={str(release_dir(row['pin'])/'bin'/name) for row in releases.values()
           for name in ('bitcoind','bitcoin-cli')}
    require(executable in paths, 'unidentified process image belongs to the original account')
    image=image_hash(root/'exe');metadata=(root/'exe').stat()
    raw=process_text(root/'cmdline').split('\0')
    require(raw[-1]=='', 'process argv is incomplete')
    groups=process_text(root/'cgroup').splitlines()
    require(len(groups)==1 and groups[0].startswith('0::/'), 'unified process cgroup authority is required')
    require(before==process_text(root/'stat').rsplit(')',1)[1].split()[19], 'process generation changed')
    return {'pid':pid,'start':before,'uids':fields['Uid'],'gids':fields['Gid'],'groups':fields['Groups'],
            'exe':executable,'image':image,'identity':[metadata.st_dev,metadata.st_ino],
            'argv':raw[:-1],'cgroup':groups[0][3:],'deleted':deleted}


def daemon_arguments():
    return [str(OPT/'current/bin/bitcoind'),'-nosettings','-conf='+str(CONF),'-datadir='+str(ROOT/'data')]


def classify_process(state, observed, releases, shutdown=False):
    account=retained_account(state);uid,gid=str(account['uid']),str(account['gid'])
    require(observed['uids']==[uid]*4 and observed['gids']==[gid]*4 and set(observed['groups'])<={gid},
            'process numeric authority differs from the retained account')
    found=[]
    for row in releases.values():
        directory=release_dir(row['pin'])/'bin'
        if observed['exe']==str(directory/'bitcoind') and observed['image']==row['daemon_sha256']:
            if observed['argv']==[str(directory/'bitcoind'),'-nosettings','-conf=/dev/null','-datadir='+str(ROOT/'data'),'--version']:
                found.append(('inspection',row['pin']));continue
            require(observed['argv']==daemon_arguments() and observed['cgroup']=='/system.slice/erpc-bitcoin.service',
                    'native process argv or cgroup differs from the owned service')
            if not shutdown:
                metadata=(directory/'bitcoind').stat()
                require(not observed['deleted'] and observed['identity']==[metadata.st_dev,metadata.st_ino],
                        'running original native image was deleted or substituted')
            found.append(('daemon',row['pin']))
        if observed['exe']==str(directory/'bitcoin-cli') and observed['image']==row['client_sha256']:
            prefix=[str(OPT/'current/bin/bitcoin-cli'),'-conf='+str(CONF),'-datadir='+str(ROOT/'data'),'-rpcclienttimeout=10']
            args=observed['argv'];suffix=args[len(prefix):]
            valid=(suffix in (['getblockchaininfo'],['getnetworkinfo'],['getindexinfo'],['getblockhash','0']) or
                   (len(suffix)==2 and suffix[0]=='getblockheader' and re.fullmatch('[a-f0-9]{64}',suffix[1])))
            require(args[:len(prefix)]==prefix and valid, 'unidentified original-account CLI invocation remains')
            found.append(('inspection',row['pin']))
    require(len(found)==1, 'original native image is unknown or ambiguous')
    return found[0]


def process_candidates(state, releases):
    account=retained_account(state);result=[]
    for path in PROC.iterdir():
        if not path.name.isdecimal() or int(path.name)==os.getpid():continue
        try:
            uid=path.lstat().st_uid
            group=process_text(path/'cgroup')
            try:executable=os.readlink(path/'exe')
            except FileNotFoundError:executable=''
            selected=executable[:-10] if executable.endswith(' (deleted)') else executable
            if uid==account['uid'] or group.splitlines()==['0::/system.slice/erpc-bitcoin.service'] or selected.endswith('/bitcoind'):
                result.append(process_record(int(path.name),releases))
        except (FileNotFoundError,ProcessLookupError):continue
        except PermissionError:raise Refused('original process inventory is not inspectable') from None
    return result


def service_properties():
    raw=run(['/usr/bin/systemctl','show',UNIT,'--no-pager','--all',
             '--property='+','.join(sorted(SERVICE_FIELDS))])
    require(len(raw)<=65536, 'service observation exceeds its bound')
    value={}
    for line in raw.decode().splitlines():
        key,separator,item=line.partition('=')
        require(separator and key not in value, 'ambiguous service observation')
        value[key]=item
    require(set(value)==SERVICE_FIELDS,
            'incomplete original service observation')
    return value


def loaded_command(value, expected):
    # systemd v255 systemctl-show.c renders strv_join(argv," ") after argv[].
    # These fixed command arguments contain no semicolons/braces; reject lists
    # rather than accepting only the first command in an unexpected override.
    require(value.count('{')==1 and value.count('}')==1, 'ambiguous loaded native command')
    match=re.fullmatch(r'\{ path=([^;]+) ; argv\[\]=(.*?) ; ignore_errors=no ; .* \}',value)
    require(match is not None and match[1].strip()==expected[0] and match[2].strip()==' '.join(expected),
            'loaded native command differs from its original unit')


def loaded_commands(value, raw):
    require(all(value[name]=='' for name in ('ExecCondition','ExecStartPost','ExecStop','ExecStopPost')) and
            value['NoNewPrivileges']=='yes','unexpected executable service hooks remain loaded')
    for field in ('ExecStart','ExecStartPre'):
        lines=[line.partition('=')[2] for line in raw.splitlines() if line.startswith(field+'=')]
        require(len(lines)==1, 'ambiguous native command in original unit')
        loaded_command(value[field],shlex.split(lines[0].lstrip('+')))


def unit_authority(state, historical=False):
    protected_paths();protected(UNIT_PATH)
    raw=UNIT_PATH.read_bytes();actual=hashlib.sha256(raw).hexdigest()
    if historical and state.get('origin')=='verified-legacy' and actual==LEGACY_UNIT_SHA256:
        require(retained_account(state)['name']=='bitcoin','legacy shutdown account history differs')
        return legacy_unit_authority()
    allowed=state.get('unit_receipts',[]) if historical else [state.get('unit_sha256')]
    require(actual in allowed, 'service file is not an original published unit')
    value=service_properties();account=retained_account(state)
    require(value['LoadState']=='loaded' and value['FragmentPath']==str(UNIT_PATH) and
            value['User']==str(account['uid']) and value['Group']==str(account['gid']) and not value['DropInPaths'],
            'loaded service does not select the original numeric account')
    loaded_commands(value,raw.decode())
    return value


def running_process(state, sockets=False):
    row=verified_native(state)
    before=unit_authority(state)
    require(before['ActiveState']=='active' and before['MainPID'].isdecimal() and int(before['MainPID'])>1,
            'original native service is not active')
    releases={native_key(row['pin']):row}
    observed=process_record(int(before['MainPID']),releases)
    require(classify_process(state,observed,releases)==('daemon',state['installed']), 'wrong original native process')
    require(before['ControlGroup']==observed['cgroup'] and before==service_properties(), 'service process changed')
    if sockets:original_listener(state,observed)
    require(observed==process_record(observed['pid'],releases), 'native generation changed during readiness observation')
    return observed


def original_listener(state, observed):
    expected=NETWORKS[state['network']][1]
    rows=[]
    for name in ('tcp','tcp6'):
        for line in process_text(PROC/'net'/name,1024*1024).splitlines()[1:]:
            fields=line.split()
            require(len(fields)>=10, 'invalid kernel listener observation')
            address,port=fields[1].split(':')
            if int(port,16)==expected and fields[3]=='0A':rows.append((name,address,fields[9]))
    require(len(rows)==1 and rows[0][:2]==('tcp','0100007F'), 'original RPC listener is absent, ambiguous or not loopback-only')
    identities=set()
    for path in (PROC/str(observed['pid'])/'fd').iterdir():
        try:identities.add(os.readlink(path))
        except FileNotFoundError:continue
    require('socket:['+rows[0][2]+']' in identities, 'RPC listener does not belong to the original native process')


def connected_peer(state, observed, connection):
    """Bind the accepted connection before reading or transmitting its cookie.

    A pre-connect listener check alone cannot prevent another UID from rebinding
    the port. Once this exact TCP peer belongs to the original PID, a new listener
    cannot take over the established connection when the native process exits.
    """
    local=connection.sock.getsockname();remote=connection.sock.getpeername()
    require(local[0]=='127.0.0.1' and remote==('127.0.0.1',NETWORKS[state['network']][1]),
            'RPC connection is outside the original loopback endpoint')
    expected_local='0100007F:'+format(remote[1],'04X')
    expected_remote='0100007F:'+format(local[1],'04X')
    deadline=time.monotonic()+2
    releases=native_releases(state)['releases']
    while True:
        rows=[]
        for line in process_text(PROC/'net/tcp',1024*1024).splitlines()[1:]:
            fields=line.split()
            require(len(fields)>=10,'invalid kernel connection observation')
            if fields[1]==expected_local and fields[2]==expected_remote and fields[3]=='01':rows.append(fields)
        require(len(rows)<=1,'ambiguous original RPC connection')
        if rows and rows[0][9]!='0':
            require(rows[0][7]==observed['uids'][0],'RPC connection belongs to another numeric account')
            sockets=set()
            for path in (PROC/str(observed['pid'])/'fd').iterdir():
                try:sockets.add(os.readlink(path))
                except FileNotFoundError:continue
            if 'socket:['+rows[0][9]+']' in sockets:
                require(process_record(observed['pid'],releases)==observed,'original RPC peer generation changed')
                return
        require(time.monotonic()<deadline,'accepted RPC socket is not owned by the original native PID')
        time.sleep(0.05)


def original_cookie(state, account):
    volume=verified_data(state,account)
    parent=ROOT/'data'
    descriptor=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(descriptor)
        require((info.st_dev,info.st_ino)==(volume['device'],state['layout']['data_inode']), 'original DATA changed before cookie access')
        if state['network']!='mainnet':
            child=os.open(NETWORKS[state['network']][0],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=descriptor)
            os.close(descriptor);descriptor=child
        info=os.fstat(descriptor)
        require(info.st_uid==account['uid'] and info.st_gid==account['gid'] and info.st_mode&0o7777==0o700 and
                info.st_dev==volume['device'], 'native network directory is not original private storage')
        cookie=os.open('.cookie',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=descriptor)
        with os.fdopen(cookie,'rb') as stream:
            info=os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid==account['uid'] and info.st_gid==account['gid'] and
                    info.st_mode&0o7777==0o600 and info.st_nlink==1 and info.st_size==75,
                    'native cookie is not an original private regular file')
            raw=bytearray(stream.read(76))
        require(re.fullmatch(b'__cookie__:[a-f0-9]{64}',raw),'native cookie format differs')
        return raw
    finally:os.close(descriptor)


def inspection_params(method, arguments):
    if method in ('getblockchaininfo','getindexinfo','getnetworkinfo'):
        require(not arguments,'unexpected inspection arguments');return []
    if method=='getblockhash':
        require(arguments==('0',),'only original genesis lookup is supported');return [0]
    require(method=='getblockheader' and len(arguments)==1 and re.fullmatch('[a-f0-9]{64}',arguments[0]),
            'unsupported inspection RPC')
    return list(arguments)


def inspect_rpc(state, method, arguments):
    params=inspection_params(method,arguments)
    account=original_runtime(state);observed=running_process(state,sockets=True)
    connection=http.client.HTTPConnection('127.0.0.1',NETWORKS[state['network']][1],timeout=10)
    raw=None
    try:
        connection.connect()
        connected_peer(state,observed,connection)
        raw=original_cookie(state,account)
        authorization='Basic '+base64.b64encode(raw).decode('ascii')
        connection.request('POST','/',body=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}),
                           headers={'Content-Type':'application/json','Authorization':authorization})
        response=connection.getresponse();body=response.read(1048577)
        require(response.status==200 and len(body)<=1048576,'original RPC is unavailable or oversized')
        value=json.loads(body)
        require(isinstance(value,dict) and set(value)=={'jsonrpc','id','result'} and value['jsonrpc']=='2.0' and
                type(value['id']) is int and value['id']==1,'original RPC is warming up or malformed')
        require(observed==running_process(state,sockets=True),'original process changed during RPC inspection')
        return value['result']
    finally:
        if raw is not None:
            for index in range(len(raw)):raw[index]=0
        connection.close()


def quiet_original(state):
    releases=native_releases(state,optional=True)['releases']
    for row in process_candidates(state,releases):
        require(classify_process(state,row,releases,shutdown=True)[0]=='inspection', 'an original native writer remains')


def signal_original(state):
    releases=native_releases(state,optional=True)['releases']
    for row in process_candidates(state,releases):
        if classify_process(state,row,releases,shutdown=True)[0]=='inspection':continue
        require(hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal'), 'Linux pidfd support is required for retained shutdown')
        descriptor=os.pidfd_open(row['pid'],0)
        try:
            require(process_record(row['pid'],releases)==row, 'original process generation changed before shutdown')
            signal.pidfd_send_signal(descriptor,signal.SIGTERM)
        finally:os.close(descriptor)


def drain_original(state):
    failures=[]
    try:
        value=service_properties()
        if value['LoadState']!='not-found':
            unit_authority(state,historical=True)
            run(['/usr/bin/systemctl','stop',UNIT],timeout=660)
    except Exception:failures.append('service stop')
    try:
        signal_original(state)
        deadline=time.monotonic()+300
        while True:
            try:quiet_original(state);break
            except Refused:
                require(time.monotonic()<deadline, 'original native writer did not exit')
                time.sleep(1)
    except Exception:failures.append('retained process drain')
    require(not failures, 'Bitcoin shutdown incomplete; original data and cancellation are retained')


def legacy_unit_authority():
    protected(UNIT_PATH)
    raw=UNIT_PATH.read_bytes()
    require(hashlib.sha256(raw).hexdigest()==LEGACY_UNIT_SHA256, 'legacy unit is not the known generated Bitcoin profile')
    value=service_properties()
    require(value['LoadState']=='loaded' and value['FragmentPath']==str(UNIT_PATH) and
            value['User']=='bitcoin' and value['Group']=='bitcoin' and not value['DropInPaths'],
            'legacy loaded unit authority is ambiguous')
    loaded_commands(value,raw.decode())
    return value


def legacy_quiet():
    for path in PROC.iterdir():
        if not path.name.isdecimal() or int(path.name)==os.getpid():continue
        try:
            groups=process_text(path/'cgroup').splitlines()
            try:image=os.readlink(path/'exe')
            except FileNotFoundError:image=''
            selected=image[:-10] if image.endswith(' (deleted)') else image
            require(groups!=['0::/system.slice/erpc-bitcoin.service'] and not selected.endswith('/bitcoind'),
                    'unproven legacy native process remains; explicit original migration is required')
        except (FileNotFoundError,ProcessLookupError):continue


def drain_legacy():
    value=service_properties()
    if value['LoadState']=='not-found':
        legacy_quiet();return
    value=legacy_unit_authority()
    run(['/usr/bin/systemctl','disable',UNIT])
    require(value['MainPID'].isdecimal(), 'legacy main process identity is unavailable')
    if int(value['MainPID'])>1:
        # The legacy unit lacks SendSIGKILL=no. Request only graceful SIGTERM;
        # never let a timeout force-kill a database writer during this upgrade.
        run(['/usr/bin/systemctl','kill','--kill-whom=main','--signal=SIGTERM',UNIT])
        deadline=time.monotonic()+600
        while service_properties()['MainPID']!='0':
            require(time.monotonic()<deadline, 'legacy original process did not exit gracefully')
            time.sleep(1)
    run(['/usr/bin/systemctl','stop',UNIT],timeout=120)
    after=service_properties()
    require(after['MainPID']=='0' and after['ActiveState'] in ('inactive','failed'), 'legacy service did not stop')
    legacy_quiet()


def disable_original_boot(state):
    if service_properties()['LoadState']=='not-found':return
    if state.get('origin') in ('fresh','verified-legacy'):unit_authority(state,historical=True)
    else:legacy_unit_authority()
    run(['/usr/bin/systemctl','disable',UNIT])

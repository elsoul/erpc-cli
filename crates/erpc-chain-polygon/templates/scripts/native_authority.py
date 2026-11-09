# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Short root socket grants and public, generation-bound native peer receipts.

Only the grant needs cross-UID executable inspection. The unprivileged adapter
checks the root-published original PID generation and SO_PEERCRED on every new
connection; it never receives ptrace or a resident root transport process.
"""
from contextlib import contextmanager
import os
import fcntl
from pathlib import Path
import re
import stat
import host
import native_peer

DIRECTORY='/run/erpc-polygon-peers'


def require(value,message):
    if not value:raise ValueError(message)


def fenced(state):
    # Names remain visible to the adapter even when their contents are private.
    require(not any(state.path('/etc/polygon/'+name).exists() for name in
                    ('preparing','stopped','retired')), 'native peer publication is fenced')


def invocation(state,component):
    value=state.proof.show(component,'InvocationID')
    require(re.fullmatch('[a-f0-9]{32}',value or '') is not None,'native service invocation is unavailable')
    return value


def socket_inode(state,component,process):
    path=str(native_peer.PATHS[component])
    rows=(state.path('/proc')/str(process['pid'])/'net/unix').read_text().splitlines()[1:]
    matches=[]
    for row in rows:
        fields=row.split(maxsplit=7)
        if len(fields)==8 and fields[7]==path:
            # Linux listening AF_UNIX SOCK_STREAM: SO_ACCEPTCON=0x10000,
            # type 0001, state SS_UNCONNECTED=01. Connected client sockets
            # alone cannot establish the authority to accept new requests.
            require(fields[3]=='00010000' and fields[4]=='0001' and fields[5]=='01'
                    and fields[6].isdigit(),'native Unix listener metadata differs')
            matches.append(fields[6])
    require(len(matches)==1 and 'socket:['+matches[0]+']' in process['descriptors'],
            'native Unix listener is not held by its original MainPID')
    return matches[0]


def grant_socket(state,component,uid,gid,reader_gid):
    """Grant the exact opened socket inode, never a subsequently replaced path."""
    path=state.path(str(native_peer.PATHS[component]))
    state.protected(str(native_peer.PATHS[component].parent.parent))
    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    descriptor=None
    try:
        parent=os.fstat(directory)
        require(stat.S_ISDIR(parent.st_mode) and parent.st_uid==uid
                and (parent.st_gid,stat.S_IMODE(parent.st_mode)) in ((gid,0o700),(reader_gid,0o710)),
                'native runtime directory has unexpected authority')
        # O_PATH is deliberately mandatory on the supported Linux host; a
        # socket is not a regular file and must never be opened for data here.
        descriptor=os.open(path.name,os.O_PATH|os.O_NOFOLLOW,dir_fd=directory)
        info=os.fstat(descriptor)
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid==uid and info.st_nlink==1
                and info.st_gid in (gid,reader_gid) and stat.S_IMODE(info.st_mode) in (0o600,0o700,0o660),
                'native socket has unexpected authority')
        pinned='/proc/self/fd/'+str(descriptor)
        os.chown(pinned,uid,reader_gid);os.chmod(pinned,0o660)
        os.fchown(directory,uid,reader_gid);os.fchmod(directory,0o710)
        # The descriptor remains pinned while checking both pathname entries.
        current=path.lstat();current_parent=path.parent.lstat()
        require((current.st_dev,current.st_ino)==(info.st_dev,info.st_ino)
                and (current_parent.st_dev,current_parent.st_ino)==(parent.st_dev,parent.st_ino),
                'native socket was rebound during its grant')
        return [parent.st_dev,parent.st_ino,info.st_dev,info.st_ino]
    finally:
        if descriptor is not None:os.close(descriptor)
        os.close(directory)


def publish(state,expected,component,authorize):
    require(component in native_peer.PATHS and expected['role']=='validator','unsupported native peer grant')
    authorize();fenced(state)
    directory=state.protected(DIRECTORY,missing=True)
    if not directory.exists():directory.mkdir(mode=0o755);host.sync_parents(directory,state.root)
    require(stat.S_ISDIR(directory.lstat().st_mode) and stat.S_IMODE(directory.lstat().st_mode)==0o755,
            'native peer receipt directory is not publicly readable and protected')
    descriptor=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        # Independent from /opt/erpc: a unit may publish while its initiating
        # deployment still holds the long-running node-operation lock.
        fcntl.flock(descriptor,fcntl.LOCK_EX)
        require(os.fstat(descriptor).st_ino==directory.lstat().st_ino,'native publication directory changed')
        return publish_locked(state,expected,component,authorize)
    finally:os.close(descriptor)


def publish_locked(state,expected,component,authorize):
    installed=authorize();fenced(state)
    require(installed['contract']==expected,'native grant belongs to another owner')
    accounts=state.accounts.verify(expected)
    before=state.proof.unit_process(component,installed)
    generation=invocation(state,component)
    inode=socket_inode(state,component,before)
    uid,gid=accounts[component]['uid'],accounts[component]['gid']
    reader_gid=accounts['parent']['gid']
    identity=grant_socket(state,component,uid,gid,reader_gid)
    after=state.proof.unit_process(component,installed)
    require((before['pid'],before['generation'])==(after['pid'],after['generation'])
            and invocation(state,component)==generation and socket_inode(state,component,after)==inode,
            'native process changed during its socket grant')
    require(authorize()==installed,'activation changed during native socket publication');fenced(state)
    receipt={'format':1,'contract':expected,'helpers':installed['helpers'],
        'profile':installed['profile_sha256'],'component':component,'invocation':generation,
        'identity':identity,'socket_inode':inode,'peer':{'pid':before['pid'],'uid':uid,'gid':gid,
        'reader_gid':reader_gid,'generation':before['generation']}}
    destination=DIRECTORY+'/'+component+'.json'
    if not state.path(destination).exists() or state.read(destination)!=receipt:
        state.write(destination,receipt,mode=0o644)
    return receipt


def read(state,expected,component,helpers,profile):
    """Nonprivileged receipt consumer; no /proc/exe or private DB access."""
    require(component in native_peer.PATHS,'unsupported native peer reader');fenced(state)
    value=state.read(DIRECTORY+'/'+component+'.json')
    require(set(value)=={'format','contract','helpers','profile','component','invocation','identity','socket_inode','peer'}
            and type(value['format']) is int and value['format']==1 and value['contract']==expected
            and value['helpers']==helpers and value['profile']==profile and value['component']==component,
            'native peer receipt belongs to another activation')
    original=state.accounts.record(expected)
    require(original is not None and original['state']=='established','original native accounts are missing')
    observed=state.accounts.observed(original)
    require(all(None not in pair for pair in observed.values()),'an original native account is missing')
    peer=value['peer'];account=original['accounts'][component]
    require(isinstance(peer,dict) and set(peer)=={'pid','uid','gid','reader_gid','generation'}
            and type(peer['pid']) is int and peer['pid']>0 and peer['uid']==account['uid']
            and peer['gid']==account['gid'] and peer['reader_gid']==original['accounts']['parent']['gid']
            and isinstance(peer['generation'],str) and peer['generation'].isdigit(),
            'native peer receipt differs from its original numeric account')
    pid=str(peer['pid']);proof=state.proof
    require(proof.show(component,'MainPID')==pid and invocation(state,component)==value['invocation']
            and state.command('systemctl','is-active',host.UNITS[component],check=False).stdout.decode().strip()=='active'
            and proof.generation(peer['pid'])==peer['generation'],'native peer service generation changed')
    # Status/cgroup files are public kernel metadata on the qualified host.
    # An unreadable proc policy fails closed rather than granting capabilities.
    directory=state.path('/proc')/pid
    status={line.split(':',1)[0]:line.split(':',1)[1].split() for line in (directory/'status').read_text().splitlines() if ':' in line}
    require(status.get('Uid')==[str(peer['uid'])]*4 and status.get('Gid')==[str(peer['gid'])]*4
            and set(status.get('Groups',[]))<={str(peer['gid'])}
            and '0::/system.slice/'+host.UNITS[component] in (directory/'cgroup').read_text().splitlines(),
            'native peer kernel identity changed')
    require(list(native_peer.identity(state.path(str(native_peer.PATHS[component])),peer['uid'],peer['reader_gid']))==value['identity'],
            'native socket no longer matches its published inode')
    require(proof.generation(peer['pid'])==peer['generation'] and proof.show(component,'MainPID')==pid
            and invocation(state,component)==value['invocation'],'native peer changed during public inspection')
    fenced(state)
    return peer


@contextmanager
def financial_lock(state):
    """Do not let a lifecycle stop overtake an already authorized outbound send."""
    import fcntl
    path=state.protected('/opt/erpc');before=path.lstat()
    descriptor=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        opened=os.fstat(descriptor)
        require((opened.st_dev,opened.st_ino)==(before.st_dev,before.st_ino),
                'financial operation lock changed while opening')
        # A mutation already in progress rejects immediately. No native health
        # read takes this lock, so an exclusive lifecycle may query its proxy.
        fcntl.flock(descriptor,fcntl.LOCK_SH|fcntl.LOCK_NB)
        after=path.lstat()
        require((after.st_dev,after.st_ino,after.st_uid,after.st_mode)==
                (before.st_dev,before.st_ino,before.st_uid,before.st_mode),
                'financial operation lock authority changed')
        fenced(state)
        yield
    finally:os.close(descriptor)

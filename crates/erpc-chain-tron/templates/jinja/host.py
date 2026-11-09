# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Linux process/socket authority and durable root-owned publication primitives."""
import ipaddress
import os
from pathlib import Path
import pwd
import re
import stat
import launch

UNITS={'node':'tron-node.service'}
USERS={'node':'tron'}
RESERVED={'node':(8090,8091,50051,50061,8545,8555,18888,9527)}


def api_ports(expected):
    return (8090,8091,50051,50061)+((8545,8555) if expected['role']=='fullnode' else ())


def sync_file(path):
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ValueError('durable publication requires a regular unlinked file')
        os.fsync(descriptor)
    finally:os.close(descriptor)


def sync_directory(path):
    descriptor=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)


def sync_parents(path,stop=Path('/')):
    path=Path(path)
    while True:
        sync_directory(path)
        if path==stop:return
        if path.parent==path:raise ValueError('durable publication escaped its host root')
        path=path.parent


def sync_tree(root):
    # Generated identity directories may contain fixed credential symlinks.
    # Their directory entries are synced; no symlink target is opened.
    for directory,children,files in os.walk(root,topdown=False,followlinks=False):
        for name in files:
            path=Path(directory)/name
            if not path.is_symlink():sync_file(path)
        for name in children:
            path=Path(directory)/name
            if path.is_symlink():raise ValueError('durable publication cannot traverse a directory link')
        sync_directory(directory)


def publish(source,destination,tree=False,stop=Path('/')):
    if tree:sync_tree(source)
    else:sync_file(source)
    source.replace(destination)
    sync_parents(destination.parent,stop)
    if source.parent!=destination.parent:sync_parents(source.parent,stop)


def unlink(path,stop=Path('/')):
    path.unlink(missing_ok=True)
    try:sync_parents(path.parent,stop)
    except Exception:
        # A failed cancellation must not permit a contemporaneous startup.
        # Re-establish the fence and propagate the storage error; no service
        # operation follows an uncertain durability result.
        fence(path,stop)
        raise


def fence(path,stop=Path('/')):
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ValueError('startup fence is not a regular private file')
        os.fchmod(descriptor,0o600);os.fsync(descriptor)
    finally:os.close(descriptor)
    sync_parents(path.parent,stop)


class Proof:
    def __init__(self,state,lookup=pwd.getpwnam):
        self.state,self.lookup=state,lookup
        self.proc=state.path('/proc');self.cgroups=state.path('/sys/fs/cgroup')

    def uid(self,component,missing=False):
        try:value=self.lookup(USERS[component]).pw_uid
        except KeyError:
            if missing:return None
            raise ValueError('dedicated runtime account is missing') from None
        if type(value) is not int or value<=0:raise ValueError('managed runtime must be unprivileged')
        return value

    def identities(self,missing=False):
        values={name:self.uid(name,missing) for name in UNITS}
        present=[uid for uid in values.values() if uid is not None]
        if len(present)!=len(set(present)):raise ValueError('managed runtime accounts must have distinct UIDs')
        return values

    def show(self,component,property):
        value=self.state.command('systemctl','show','--property='+property,'--value',UNITS[component]).stdout.decode().strip()
        return value

    def generation(self,pid):
        text=(self.proc/str(pid)/'stat').read_text()
        tail=text.rsplit(')',1)
        if len(tail)!=2 or text.split(' ',1)[0]!=str(pid):raise ValueError('invalid process stat identity')
        fields=tail[1].split()
        if len(fields)<20 or not fields[19].isdigit():raise ValueError('process generation is unavailable')
        return fields[19]

    def process(self,pid):
        directory=self.proc/str(pid)
        first=self.generation(pid)
        values={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in (directory/'status').read_text().splitlines() if ':' in line}
        uids=values.get('Uid','').split()
        if len(uids)!=4 or not all(value.isdigit() for value in uids):raise ValueError('process UID is unreadable')
        gids=values.get('Gid','').split();groups=values.get('Groups','').split()
        if len(gids)!=4 or not all(value.isdigit() for value in (*gids,*groups)):raise ValueError('process groups are unreadable')
        state=values.get('State','').split()[0]
        if state in ('Z','X'):
            if self.generation(pid)!=first:raise ValueError('PID changed while inspecting an exited process')
            return {'dead':True,'pid':pid,'generation':first}
        try:executable=os.readlink(directory/'exe')
        except FileNotFoundError:
            if not directory.exists():raise
            executable=''  # Kernel thread: no executable or command line.
        deleted=executable.endswith(' (deleted)');executable=executable.removesuffix(' (deleted)')
        # Fixture roots model kernel-visible absolute paths without touching /opt.
        if self.state.root!=Path('/') and executable.startswith(str(self.state.root)+'/'):
            executable='/'+str(Path(executable).relative_to(self.state.root))
        arguments=(directory/'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        if not executable and any(arguments):raise ValueError('live userspace executable identity is unavailable')
        cgroup=(directory/'cgroup').read_text()
        descriptors=[]
        for descriptor in (directory/'fd').iterdir():
            try:descriptors.append(os.readlink(descriptor))
            except FileNotFoundError:
                if descriptor.exists():raise ValueError('process descriptor became unreadable') from None
        if self.generation(pid)!=first:raise ValueError('PID was reused during process inspection')
        return {'dead':False,'pid':pid,'generation':first,'uids':tuple(map(int,uids)),'gids':tuple(map(int,gids)),'groups':tuple(map(int,groups)),
            'executable':executable,'deleted':deleted,'arguments':arguments,'cgroup':cgroup,'descriptors':descriptors}

    def group(self,component):
        expected='/system.slice/'+UNITS[component]
        observed=self.show(component,'ControlGroup')
        if observed and observed!=expected:raise ValueError('managed service has an unexpected cgroup')
        directory=self.cgroups/expected.lstrip('/')
        # A missing unit/cgroup is not proof that its dedicated UID stopped.
        if directory.is_symlink() or directory.parent.is_symlink():raise ValueError('service cgroup is redirected')
        return expected,directory

    def quiescent(self,components=None,ignore_self=False):
        components=tuple(UNITS) if components is None else components
        identities=self.identities(missing=True)
        owners={identities[name] for name in components}-{None}
        retained=self.state.accounts.retained_uid()
        if retained is not None:owners.add(retained)
        for component in components:
            _,directory=self.group(component)
            if directory.exists():
                for file in directory.rglob('cgroup.procs'):
                    if file.is_symlink():raise ValueError('a managed cgroup is redirected')
                    pids=file.read_text().split()
                    if any(not pid.isdigit() or not(ignore_self and int(pid)==os.getpid()) for pid in pids):
                        raise ValueError('a managed cgroup still has processes')
        entries=list(self.proc.iterdir())
        processes=[int(path.name) for path in entries if path.name.isdecimal()]
        if not processes:raise ValueError('Linux process table is unavailable')
        data=str(self.state.path('/var/lib/tron'))
        for pid in processes:
            if ignore_self and pid==os.getpid():continue
            try:value=self.process(pid)
            except FileNotFoundError:
                if (self.proc/str(pid)).exists():raise ValueError('live process metadata became unreadable') from None
                continue
            if value['dead']:continue
            native=any(Path(os.fsdecode(arg)).name=='FullNode.jar' for arg in value['arguments'])
            # A foreign executable may still write a managed database. Check
            # every visible process's argv and open descriptors, not its title.
            paths=[os.fsdecode(arg) for arg in value['arguments']]+value['descriptors']
            managed=any(data in item or '/var/lib/tron' in item for item in paths)
            if owners.intersection(value['uids']) or native or managed:
                raise ValueError('an unmanaged TRON writer or runtime process remains; explicit operator recovery required')

    def unoccupied(self,components=None):
        components=tuple(UNITS) if components is None else components
        reserved={port for name in components for port in RESERVED[name]}
        if any(row[0] in reserved for row in self.listening(udp=True)):
            raise ValueError('unowned listeners occupy managed TRON ports')

    def initial(self):
        self.quiescent();self.unoccupied()

    def can_start(self,expected,release):
        self.identities()
        active=self.state.command('systemctl','is-active',UNITS['node'],check=False).stdout.decode().strip()
        if active=='active':self.listener(expected,release)
        elif active in ('inactive','failed'):
            self.quiescent();self.unoccupied()
        else:raise ValueError('managed service transition is incomplete')

    def startable(self):
        self.identities()
        self.quiescent(ignore_self=True);self.unoccupied()

    def listening(self,udp=False):
        result=[]
        for family in (('tcp','tcp6','udp','udp6') if udp else ('tcp','tcp6')):
            for line in (self.proc/'net'/family).read_text().splitlines()[1:]:
                fields=line.split()
                if len(fields)<10:raise ValueError('TCP ownership table is malformed')
                if family.startswith('tcp') and fields[3]!='0A':continue
                encoded,port=fields[1].split(':')
                raw=bytes.fromhex(encoded)
                raw=raw[::-1] if family in ('tcp','udp') else b''.join(raw[index:index+4][::-1] for index in range(0,16,4))
                address=str(ipaddress.ip_address(raw))
                if not fields[7].isdigit() or not fields[9].isdigit():raise ValueError('listener ownership is unavailable')
                result.append((int(port,16),address,int(fields[7]),fields[9]))
        return result

    def listener(self,expected,release):
        record=self.state.accounts.verify(expected)
        component='node';uid=self.identities()[component]
        if uid!=record['uid']:raise ValueError('current runtime UID differs from original authority')
        if self.state.command('systemctl','is-active',UNITS[component],check=False).stdout.decode().strip()!='active':
            raise ValueError('required managed service is not active')
        pid=self.show(component,'MainPID')
        if not pid.isdigit() or int(pid)<=0:raise ValueError('required service has no MainPID')
        value=self.process(int(pid));group,directory=self.group(component)
        if (value['dead'] or value['uids']!=(uid,)*4 or value['gids']!=(record['gid'],)*4
                or set(value['groups'])-{record['gid']} or '0::'+group not in value['cgroup'].splitlines()
                or pid not in (directory/'cgroup.procs').read_text().split()):
            raise ValueError('listener process differs from its dedicated UID/cgroup')
        arguments=launch.arguments(expected,release)
        binary=self.state.path(arguments[0]).resolve()
        executable='/'+str(binary.relative_to(self.state.root.resolve())) if self.state.root!=Path('/') else str(binary)
        if value['deleted'] or value['executable']!=executable or value['arguments']!=[arg.encode() for arg in arguments]:
            raise ValueError('listener is not the expected JVM and immutable client JAR profile')
        self.state.protected(executable)
        running=(self.proc/pid/'exe').stat();installed_file=binary.stat()
        if (running.st_dev,running.st_ino)!=(installed_file.st_dev,installed_file.st_ino):
            raise ValueError('running JVM inode differs from the selected distribution file')
        sockets={match.group(1) for item in value['descriptors'] if (match:=re.fullmatch(r'socket:\[(\d+)\]',item))}
        table=self.listening();bound=[]
        for port in api_ports(expected):
            listeners=[row for row in table if row[0]==port]
            if not listeners or any(row[2]!=uid or row[3] not in sockets for row in listeners):
                raise ValueError('a native API socket is missing or belongs to another process')
            bound.extend(listeners)
        if self.generation(int(pid))!=value['generation'] or self.show(component,'MainPID')!=pid:
            raise ValueError('native process changed during listener inspection')
        return (pid,value['generation'],tuple(sorted(bound)))

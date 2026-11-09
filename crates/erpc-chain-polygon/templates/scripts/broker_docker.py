# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fixed local root daemon boundary for the dedicated validator broker."""
import json
import socket
import stat
import struct
import host
from state import unique

CONFIG='/etc/erpc/polygon/docker'
SOCKET='/run/docker.sock'
# docker/cli config.LoadDefaultConfigFile auto-detects a credential helper when
# ContainsAuth is false. A nonempty map with an explicitly empty public-registry
# record prevents that discovery without supplying any credential or provider.
LOCAL_CONFIG={'auths':{'docker.io':{}}}


def require(value,message):
    if not value:raise ValueError(message)


def decode(raw):
    require(isinstance(raw,bytes) and 0<len(raw)<=2*1024*1024,'Docker public metadata exceeds its bound')
    return json.loads(raw,object_pairs_hook=unique)


def start_allowed(state,expected):
    require(expected.get('role')=='validator','only validator initialization may provision a broker daemon')
    state.ownership(expected);state.namespaces();state.accounts.verify(expected)
    active=state.command('systemctl','is-active','docker.service',check=False).stdout.decode().strip()
    if active=='active':return {'already_running':True}
    require(active in ('inactive','failed'),'Docker service is in an unknown transition')
    # Starting a pre-existing stopped daemon can also restart foreign
    # containers. Only a fresh distribution namespace is automatically started;
    # an existing stopped installation needs explicit operator recovery first.
    for name in ('/etc/docker/daemon.json','/var/lib/docker','/var/lib/containerd'):
        path=state.protected(name,missing=True)
        if path.exists():
            require(name!='/etc/docker/daemon.json' and path.is_dir() and not any(path.iterdir()),
                    'existing stopped Docker state cannot be implicitly started or adopted')
    return {'fresh_daemon':True}


class Docker:
    def __init__(self,state,expected,create=False,connect=socket.socket):
        require(expected.get('role')=='validator','broker daemon operations require validator ownership')
        state.ownership(expected);state.namespaces()
        self.state=state
        executable=state.protected('/usr/bin/docker')
        require(executable.is_file() and executable.stat().st_mode&0o111,'fixed Docker CLI is unavailable')
        state.protected('/run')
        path=state.path(SOCKET);before=path.lstat()
        require(stat.S_ISSOCK(before.st_mode) and before.st_uid==state.owner and before.st_nlink==1
                and not before.st_mode&0o007,'Docker socket is not root-owned with restricted access')
        stream=connect(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            stream.settimeout(10);stream.connect(str(path))
            pid,uid,_gid=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
            require(pid>0 and uid==0,'Docker daemon must be the original local rootful service')
            after=path.lstat()
            require((before.st_dev,before.st_ino,before.st_uid,before.st_mode,before.st_nlink)==
                    (after.st_dev,after.st_ino,after.st_uid,after.st_mode,after.st_nlink),
                    'Docker socket changed during peer verification')
        finally:stream.close()
        directory=state.protected(CONFIG,missing=create)
        if not directory.exists():
            require(create,'original broker CLI namespace is missing')
            directory.mkdir(mode=0o700);host.sync_parents(directory,state.root)
        require(directory.is_dir() and stat.S_IMODE(directory.stat().st_mode)==0o700,
                'broker CLI namespace must remain private and root-owned')
        require({entry.name for entry in directory.iterdir()}<={'config.json','config.pending'},
                'unrecognized Docker context or credential configuration cannot be adopted')
        file=CONFIG+'/config.json'
        pending=CONFIG+'/config.pending'
        if not state.path(file).exists():
            require(create,'original Docker configuration is missing')
            if state.path(pending).exists():
                require(state.read(pending)==LOCAL_CONFIG,'unknown interrupted Docker configuration cannot be adopted')
                host.publish(state.protected(pending),state.path(file),stop=state.root)
            else:state.write(file,LOCAL_CONFIG)
        require(state.read(file)==LOCAL_CONFIG,'broker must not use external Docker contexts or credential helpers')
        if state.path(pending).exists():
            require(state.read(pending)==LOCAL_CONFIG,'unknown pending Docker configuration cannot be discarded')
            host.unlink(state.protected(pending),state.root)
        self.prefix=['/usr/bin/docker','--host','unix://'+SOCKET,'--config',CONFIG]
        info=decode(self.call('info','--format','{{json .}}',timeout=30).stdout)
        security=info.get('SecurityOptions')
        require(info.get('OSType')=='linux' and info.get('CgroupVersion')=='2' and info.get('CgroupDriver')=='systemd'
                and all(info.get(name) is True for name in ('MemoryLimit','SwapLimit','PidsLimit','CpuCfsQuota'))
                and isinstance(security,list)
                and all(isinstance(item,str) for item in security)
                and not any('rootless' in item or 'userns' in item for item in security),
                'broker requires the rootful Linux daemon with original host UIDs and cgroup v2')

    def call(self,*args,**kwargs):
        return self.state.command(*self.prefix,*args,**kwargs)

    def inspect(self,kind,identity):
        require(kind in ('image','container'),'unsupported Docker metadata kind')
        rows=decode(self.call(kind,'inspect',identity,timeout=30).stdout)
        require(isinstance(rows,list) and len(rows)==1 and isinstance(rows[0],dict),'Docker metadata is missing or ambiguous')
        return rows[0]

# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert kernel/udev observations for actual temporary-directory volume callers."""
import json
import os
from pathlib import Path
import subprocess
from unittest.mock import patch


def attach(case,state):
    import volume
    for name,value in {
        '/etc/os-release':'ID=ubuntu\nVERSION_ID="24.04"\n',
        '/proc/meminfo':'MemTotal:       64000000 kB\n',
        '/proc/self/status':'Cpus_allowed_list: 0-15\n',
        '/proc/self/cgroup':'0::/\n',
        '/sys/fs/cgroup/cgroup.controllers':'cpu memory pids\n',
        '/sys/fs/cgroup/cgroup.subtree_control':'cpu memory\n',
        '/sys/fs/cgroup/cpu.max':'max 100000\n',
        '/sys/fs/cgroup/memory.max':'max\n',
    }.items():
        path=state.path(name);path.parent.mkdir(parents=True,exist_ok=True)
        if not path.exists():path.write_text(value)
    state.volume_uuid='00000000-0000-0000-0000-000000000001'
    state.volume_mounts=[];state.volume_observations=[]
    original_command=state.command
    def command(*args,**kwargs):
        if args[0]=='/usr/bin/systemd-detect-virt':return subprocess.CompletedProcess(args,1,b'none\n',b'')
        if args[0]!='/usr/bin/findmnt':return original_command(*args,**kwargs)
        state.volume_observations.append(args)
        if '--list' in args:
            data={'filesystems':[{'target':'/'},*({'target':str(path)} for path in state.volume_mounts)]}
        else:
            path=Path(args[args.index('--target')+1]);info=path.stat()
            data={'filesystems':[{'uuid':state.volume_uuid,'fstype':'ext4','options':'rw,relatime',
                'maj:min':str(os.major(info.st_dev))+':'+str(os.minor(info.st_dev))}]}
        return subprocess.CompletedProcess(args,0,json.dumps(data).encode(),b'')
    def device(current,identifier):
        if identifier!=current.volume_uuid:raise ValueError('inert original udev UUID is no longer present')
        path=current.path(volume.DATA)
        while not path.exists():path=path.parent
        return path.stat().st_dev
    entry=patch.object(state,'command',side_effect=command);entry.start();case.addCleanup(entry.stop)
    entry=patch.object(volume,'uuid_device',side_effect=device);entry.start();case.addCleanup(entry.stop)
    return volume


def bind(state,expected):
    import volume
    state.write('/etc/polygon/contract.json',dict(expected,runtime_protocol=3))
    volume.reserve(state,expected)

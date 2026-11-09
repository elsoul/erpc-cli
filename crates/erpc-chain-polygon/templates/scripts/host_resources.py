# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Runtime CPU/RAM budgets, including every effective cgroup v2 ancestor."""
from pathlib import Path
import re


def require(value,message):
    if not value:raise ValueError(message)


def read(state,name,limit=65536):
    try:
        with state.path(name).open('rb') as stream:value=stream.read(limit+1)
    except OSError:raise ValueError('kernel resource observation is unavailable') from None
    require(len(value)<=limit,'kernel resource observation exceeds its bound')
    return value.decode()


def cpus(value):
    require(isinstance(value,str) and re.fullmatch(r'[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*',value),
            'effective CPU affinity is unavailable')
    seen=set()
    for part in value.split(','):
        fields=part.split('-');first=int(fields[0]);last=int(fields[-1])
        require(first<=last<=1048576,'effective CPU affinity is invalid')
        selected=set(range(first,last+1));require(not seen.intersection(selected),'CPU affinity repeats a processor')
        seen.update(selected)
    return len(seen)


def verify(state,expected):
    os_info={}
    for line in read(state,'/etc/os-release').splitlines():
        if '=' not in line or line.startswith('#'):continue
        key,value=line.split('=',1)
        require(key not in os_info,'operating system identity is ambiguous')
        os_info[key]=value.strip('"')
    require(os_info.get('ID')=='ubuntu' and os_info.get('VERSION_ID')=='24.04',
            'managed Polygon startup requires the qualified Ubuntu 24.04 profile')
    memory=re.findall(r'^MemTotal:\s+([0-9]+) kB$',read(state,'/proc/meminfo'),re.M)
    affinity=re.findall(r'^Cpus_allowed_list:\s+([^\n]+)$',read(state,'/proc/self/status'),re.M)
    require(len(memory)==len(affinity)==1,'effective CPU/RAM observations are missing or ambiguous')
    effective_cpu=cpus(affinity[0].strip());effective_memory=int(memory[0])*1024
    groups=read(state,'/proc/self/cgroup').splitlines()
    require(len(groups)==1 and groups[0].startswith('0::/'),'visible unified cgroup v2 budgets are required')
    group=groups[0][3:];parts=Path(group).parts
    require(group.startswith('/') and len(parts)<=64
            and (group=='/' or all(part not in ('','.','..') for part in group.split('/')[1:])),
            'kernel cgroup path is invalid')
    relative=Path('sys/fs/cgroup')
    directories=[relative]
    for part in parts[1:]:relative/=part;directories.append(relative)
    detected=state.command('/usr/bin/systemd-detect-virt','--container',check=False,timeout=15)
    require(detected.returncode==1 and detected.stdout.decode().strip()=='none',
            'native Polygon requires the full Ubuntu host resource hierarchy, not a nested container')
    available=set(read(state,'/sys/fs/cgroup/cgroup.controllers').split())
    require({'cpu','memory'}<=available,'qualified kernel CPU and memory controllers are unavailable')
    parent_enabled=set()
    for index,directory in enumerate(directories):
        path=state.root/directory
        require(not path.is_symlink() and path.is_dir(),'kernel resource hierarchy cannot be redirected')
        for controller,name in (('cpu','cpu.max'),('memory','memory.max')):
            file=path/name
            if not file.exists() and not file.is_symlink():
                # The hierarchy root has no per-group limits. A disabled child
                # controller inherits the already inspected ancestor's budget.
                require(index==0 or controller not in parent_enabled,
                        'enabled kernel resource limit is missing')
                continue
            require(not file.is_symlink() and file.is_file(),'kernel resource limits cannot be redirected')
            value=read(state,'/'+str(directory/name)).strip()
            if controller=='cpu':
                quota=value.split()
                require(len(quota)==2 and quota[1].isdigit() and 0<int(quota[1])<=10**9,
                        'CPU cgroup budget is invalid')
                if quota[0]!='max':
                    require(quota[0].isdigit() and 0<int(quota[0])<2**64,'CPU cgroup quota is invalid')
                    effective_cpu=min(effective_cpu,int(quota[0])//int(quota[1]))
            elif value!='max':
                require(value.isdigit() and 0<int(value)<2**64,'memory cgroup budget is invalid')
                effective_memory=min(effective_memory,int(value))
        parent_enabled=set(read(state,'/'+str(directory/'cgroup.subtree_control')).split())
    # Match the existing frontend's usable-MemTotal floor, allowing kernel
    # reservations on provisioned64GB/16GB machines. These are ERPC runtime
    # admission floors, not a claim that CPU/I/O contention was benchmarked.
    minimum=60_000_000 if expected['network']=='mainnet' else 15_000_000
    require(effective_cpu>=16 and effective_memory>=minimum*1024,
            'Polygon effective CPU/RAM budget is below its reviewed runtime floor; stop/destroy remain available')
    return {'effective_logical_cpus':effective_cpu,'effective_memory_bytes':effective_memory,
        'minimum_logical_cpus':16,'minimum_reported_memory_kib':minimum}

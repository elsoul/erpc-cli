# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Shared read-only native platform qualification, before any key or host write."""
import os
from pathlib import Path
import platform
import re
import shlex

def require(condition,message):
    if not condition:raise ValueError(message)

def operating_system(OS_RELEASE,VENDOR_RELEASE,read,root_directory):
    root_directory(OS_RELEASE.parent)
    path = OS_RELEASE
    if path.is_symlink():
        require(path.lstat().st_uid == 0, 'untrusted OS release link')
        target = Path(os.readlink(path))
        if not target.is_absolute(): target = path.parent / target
        require(os.path.normpath(target) == str(VENDOR_RELEASE), 'OS release leaves its vendor namespace')
        path = VENDOR_RELEASE
        root_directory(path.parent)
    values = {}
    for line in read(path, 16384).decode().splitlines():
        key, separator, value = line.partition('=')
        if key not in ('ID', 'VERSION_ID'): continue
        parsed = shlex.split(value)
        require(separator and key not in values and len(parsed) == 1, 'ambiguous OS release')
        values[key] = parsed[0]
    require(values == {'ID': 'ubuntu', 'VERSION_ID': '24.04'}, 'native profile requires qualified Ubuntu 24.04')


def platform_facts(role,network,run,operating_system,CPUINFO):
    require(role in ('rpc', 'validator') and network in ('mainnet', 'testnet')
            and platform.system() == 'Linux'
            and platform.machine() == 'x86_64', 'native profile requires Linux x86-64')
    operating_system()
    version = run(['/usr/bin/systemctl', '--version']).splitlines()
    require(version and re.match(r'^systemd 255(?: |$)', version[0]),
            'native credential delivery requires qualified systemd 255')
    threads = os.cpu_count() or 0
    memory = os.sysconf('SC_PHYS_PAGES') * os.sysconf('SC_PAGE_SIZE')
    # Usable-memory floors allow firmware/kernel reservation on nominal RAM.
    # Recommended hosts have >=384 GiB (validator) /512 GiB (RPC), including
    # room for the separate 48 GiB compiler. A testnet validator's floor is for
    # a nominal 128 GiB machine, the size ERPC buys for one; a build next to a
    # running validator has little room there. These are ERPC policies, not a
    # throughput, physical-core or network benchmark.
    minimum_threads, minimum_memory = (
        (32, 480 * 1024**3) if role == 'rpc'
        else (24, 120 * 1024**3) if network == 'testnet'
        else (24, 300 * 1024**3))
    require(threads >= minimum_threads and memory >= minimum_memory, 'insufficient native runtime and compiler capacity')
    with CPUINFO.open('rb') as source: raw = source.read(4 * 1024 * 1024 + 1)
    require(len(raw) <= 4 * 1024 * 1024, 'CPU feature metadata exceeds its bound')
    flags = [set(line.partition(b':')[2].split()) for line in raw.splitlines() if line.startswith(b'flags\t') or line.startswith(b'flags ')]
    require(len(flags) >= minimum_threads and all({b'avx2', b'sha_ni'} <= values for values in flags), 'native profile requires AVX2 and SHA CPU features')
    return {'os': 'ubuntu 24.04', 'systemd': 255, 'logical_threads': threads, 'memory_bytes': memory}


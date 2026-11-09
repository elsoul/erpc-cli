#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Remaining initial-sync estimate and operating headroom on the actual DB filesystem."""
import os
from pathlib import Path
import re
import stat
import sys


def check(total_kb,free_kb,history,allocated_kb):
    if history not in ('full','archive') or any(type(v)is not int or v<0 for v in (total_kb,free_kb,allocated_kb)):
        raise ValueError('invalid Avalanche capacity inputs')
    minimum=13_000_000_000 if history=='archive' else 900_000_000
    # A partial DB does not establish completed sync. Only actual allocated
    # original-account blocks reduce this estimate; sparse apparent bytes do not.
    needed=max(100_000_000,minimum-allocated_kb)
    if total_kb<minimum or free_kb<needed:
        raise ValueError('insufficient remaining initial-sync budget or operating headroom')
    return needed


def allocation(root,network,uid,mountinfo=Path('/proc/self/mountinfo')):
    if network not in ('mainnet','fuji') or type(uid)is not int or uid<=0:
        raise ValueError('invalid Avalanche database authority')
    info=root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=uid or info.st_mode&0o077:
        raise ValueError('Avalanche data root authority changed')
    # Device checks also inspect every nested directory. The mount table closes
    # the same-device bind-mount case that st_dev alone cannot distinguish.
    for line in mountinfo.read_text().splitlines():
        fields=line.split()
        if len(fields)<6:raise ValueError('mount authority is unavailable')
        name=re.sub(r'\\([0-7]{3})',lambda value:chr(int(value[1],8)),fields[4])
        mounted=Path(name)
        if root in mounted.parents:raise ValueError('nested Avalanche data mounts are refused')
    db=root/'db'
    pending=[db] if db.exists() or db.is_symlink() else []
    seen=set();allocated=0;count=0
    while pending:
        path=pending.pop();metadata=path.lstat();count+=1
        if count>1000000:raise ValueError('Avalanche DB tree exceeds its inspection bound')
        if metadata.st_dev!=info.st_dev or metadata.st_uid!=uid:
            raise ValueError('Avalanche DB ownership or filesystem changed')
        if stat.S_ISDIR(metadata.st_mode):
            # Verify the whole DB namespace, but credit only this network.
            pending.extend(path.iterdir())
        elif stat.S_ISREG(metadata.st_mode):
            inode=(metadata.st_dev,metadata.st_ino)
            if root/'db'/network in path.parents and inode not in seen:
                seen.add(inode);allocated+=metadata.st_blocks*512
        else:raise ValueError('Avalanche database links or special files are refused')
    return allocated//1024


def inspect(root,history,network,uid,mountinfo=Path('/proc/self/mountinfo')):
    allocated=allocation(root,network,uid,mountinfo)
    disk=os.statvfs(root)
    return check(disk.f_blocks*disk.f_frsize//1024,disk.f_bavail*disk.f_frsize//1024,history,allocated)


def main():
    history,network=sys.argv[1:]
    root=Path('/var/lib/avalanchego')
    inspect(root,history,network,root.lstat().st_uid)

if __name__=='__main__':main()

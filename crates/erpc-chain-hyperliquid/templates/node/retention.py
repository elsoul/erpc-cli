#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Unprivileged retention of public outputs only; retain the newest two snapshots."""
import os
from pathlib import Path
import re
import stat
import time

ROOT = Path('/var/lib/erpc-hyperliquid/home/hl/data')
OUTPUTS = ('replica_cmds', 'node_logs', 'node_trades', 'node_fills', 'node_twap_statuses',
           'node_order_statuses', 'node_raw_book_diffs', 'hip3_oracle_updates', 'misc_events',
           'system_and_core_writer_actions', 'mempool_txs')


def collect(directory):
    if not directory.exists():
        return []
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError('output directory is indirect')
    result = []
    pending = [directory]
    while pending:
        current = pending.pop()
        for entry in current.iterdir():
            info = entry.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ValueError('node output links require inspection')
            if stat.S_ISDIR(info.st_mode):
                pending.append(entry)
            elif stat.S_ISREG(info.st_mode):
                result.append((entry, info.st_mtime, info.st_dev, info.st_ino))
            else:
                raise ValueError('unexpected node output file type')
            if len(result) + len(pending) > 2_000_000:
                raise ValueError('node retention scan exceeded bounds')
    return result


def prune(root, now=None):
    current = time.time() if now is None else now
    if not root.is_dir() or root.is_symlink():
        raise ValueError('node output root is unavailable')
    candidates = []
    for name in OUTPUTS:
        candidates += collect(root / name)
    snapshots = collect(root / 'periodic_abci_states')
    valid_snapshots = []
    for entry in snapshots:
        path = entry[0]
        if re.fullmatch('[0-9]+\\.rmp', path.name):
            valid_snapshots.append((int(path.stem), entry))
    retained = {entry[0] for _, entry in sorted(valid_snapshots, key=lambda value: value[0], reverse=True)[:2]}
    candidates += [entry for _, entry in valid_snapshots if entry[0] not in retained]
    removed = 0
    for path, modified, device, inode in candidates:
        if current - modified <= 48 * 3600:
            continue
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino, info.st_mtime) != (device, inode, modified):
            raise ValueError('node output changed during retention')
        path.unlink()
        removed += 1
    return removed


if __name__ == '__main__':
    if os.geteuid() == 0:
        raise SystemExit('retention must run as the dedicated native account')
    print('removed_public_outputs=' + str(prune(ROOT)))

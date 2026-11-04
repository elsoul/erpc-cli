#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Read-only initial database capacity versus existing-database operating headroom."""
import os
from pathlib import Path
import sys


def check(total_kb, free_kb, history, existing_database):
    if history not in ('full', 'archive'):
        raise ValueError('unknown history policy')
    minimum = 13_000_000_000 if history == 'archive' else 900_000_000
    needed = 100_000_000 if existing_database else minimum
    if total_kb < minimum or free_kb < needed:
        raise ValueError('insufficient initial-sync space or operating headroom')


def main():
    history, network = sys.argv[1:]
    if network not in ('mainnet', 'fuji'):
        raise ValueError('unknown network')
    root = Path('/var/lib/avalanchego')
    db = root / 'db' / network
    existing = db.is_dir() and any(db.iterdir())
    disk = os.statvfs(root)
    check(disk.f_blocks * disk.f_frsize // 1024,
          disk.f_bavail * disk.f_frsize // 1024, history, existing)


if __name__ == '__main__':
    main()

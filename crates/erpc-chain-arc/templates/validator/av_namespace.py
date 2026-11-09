#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Authenticate owned namespace ancestors before publication or root interpretation."""
import os
import re
import stat

from arc_files import require
from av_files import ROOT, NAMESPACE
from av_process import UNITS
import av_events

PRIVATE = {'lock', 'owner.json', 'operation.json', 'startup-revoked.json', 'retired.json',
           'consensus-key.cred', 'consensus-key.staged', 'consensus-key.restore', 'signer-ca.pem'}
DIRECTORIES = {'cipher-history', 'intents', 'units', 'events'}
FIREWALL = 'erpc-arc-validator-firewall.service'


def private_tree(context, fresh=False, pending_owner=False):
    root = context.protected(ROOT, directory=True, missing=True)
    if not root.exists():
        return
    require(not root.stat().st_mode & 0o077, 'Arc validator authority directory is not private')
    entries = list(root.iterdir())
    names = {item.name for item in entries}
    require(not fresh or names <= {'lock'} or
            (pending_owner and 'owner.json.pending' in names and names <= {'lock', 'owner.json.pending'}),
            'unowned Arc validator authority artifacts cannot be adopted')
    require(len(entries) <= 2 * len(PRIVATE) + len(DIRECTORIES), 'unknown Arc validator authority contents')
    for entry in entries:
        virtual = ROOT + '/' + entry.name
        if entry.name in DIRECTORIES:
            folder = context.protected(virtual, directory=True)
            require(not folder.stat().st_mode & 0o077, 'Arc validator authority subdirectory is not private')
            rows = list(folder.iterdir())
            require(len(rows) <= 100000, 'Arc validator retained-authority bound exceeded')
            pattern = (av_events.PATTERN if entry.name == 'events' else '[0-9a-f]{64}[.]cred(?:[.]pending)?' if entry.name == 'cipher-history' else
                       '[0-9a-f]{64}[.]json(?:[.]pending)?' if entry.name == 'units' else
                       '[0-9a-f]{32}[.]json(?:[.]pending)?')
            for row in rows:
                require(re.fullmatch(pattern, row.name), 'unknown retained Arc validator authority entry')
                path = context.protected(virtual + '/' + row.name)
                require(not path.stat().st_mode & 0o077, 'retained Arc validator authority is not private')
        else:
            name = entry.name.removesuffix('.pending')
            require(name in PRIVATE, 'unknown Arc validator authority entry')
            path = context.protected(virtual)
            require(not path.stat().st_mode & 0o077, 'Arc validator authority file is not private')


def helper_tree(context, fresh=False):
    root = context.protected(NAMESPACE, missing=True, directory=True)
    if not root.exists():
        return
    require(set(os.listdir(root)) <= {'current', 'current.pending', 'releases'},
            'unknown Arc validator helper namespace entry')
    require(not fresh or not os.listdir(root), 'unowned Arc validator helpers cannot be adopted')
    releases = context.protected(NAMESPACE + '/releases', missing=True, directory=True)
    if releases.exists():
        rows = list(releases.iterdir())
        require(len(rows) <= 10000, 'Arc validator helper release bound exceeded')
        for release in rows:
            require(re.fullmatch('[0-9a-f]{64}(?:[.]pending)?', release.name), 'unknown Arc helper release')
            folder = context.protected(NAMESPACE + '/releases/' + release.name, directory=True)
            for item in folder.iterdir():
                require(item.name != '__pycache__' and re.fullmatch('[A-Za-z0-9_.-]+', item.name),
                        'unknown cached or linked validator helper content')
                context.protected(NAMESPACE + '/releases/' + release.name + '/' + item.name)
    for name in ('current', 'current.pending'):
        pointer = root / name
        try:
            info = pointer.lstat()
        except FileNotFoundError:
            continue
        require(stat.S_ISLNK(info.st_mode) and info.st_uid == context.owner and
                re.fullmatch('releases/[0-9a-f]{64}', os.readlink(pointer)),
                'only the original closed validator helper pointer is accepted')
        # Missing original helper bytes do not grant execution authority, but a
        # sealed carried stop/recovery must still reach the original owner record.
        context.protected(NAMESPACE + '/' + os.readlink(pointer), directory=True, missing=True)


def unit_tree(context, fresh=False):
    context.protected('/etc/systemd/system', missing=True, directory=True)
    for name in (*UNITS.values(), FIREWALL):
        unit = context.protected('/etc/systemd/system/' + name, missing=True)
        require(not fresh or not unit.exists(), 'unowned validator unit cannot be adopted')
        folder = context.protected('/etc/systemd/system/' + name + '.d', missing=True, directory=True)
        if not folder.exists():
            continue
        require(not fresh or not os.listdir(folder), 'unowned validator service drop-ins cannot be adopted')
        require(set(os.listdir(folder)) <= {'50-erpc-firewall-guard.conf', '50-erpc-firewall-guard.conf.new'},
                'unknown validator service drop-in can override its authority boundary')
        for entry in folder.iterdir():
            context.protected('/etc/systemd/system/' + name + '.d/' + entry.name)


def firewall_tree(context, fresh=False):
    family = '/etc/erpc/arc-validator'
    directory = context.protected(family, missing=True, directory=True)
    if not directory.exists():
        return
    entries = set(os.listdir(directory))
    require(entries <= {'authority', 'startup-revoked', 'startup-revoked.new',
                        'previous.nft', 'previous.new', 'pending.nft', 'pending.json', 'pending.new',
                        'confirmed.json', 'confirmed.new', 'firewall.nft', 'firewall.new'},
            'unknown validator ingress state is retained')
    require(not fresh or entries <= {'authority'}, 'unowned validator ingress state cannot be adopted')
    for name in entries - {'authority'}:
        path = context.protected(family + '/' + name)
        require(not path.stat().st_mode & 0o077, 'original validator ingress state is not private')


def check(context, fresh=False, pending_owner=False):
    private_tree(context, fresh, pending_owner)
    firewall_tree(context, fresh)
    helper_tree(context, fresh)
    unit_tree(context, fresh)
    context.protected('/usr/local/lib/erpc/rpc-firewall.py', missing=True)
    native = context.protected('/opt/arc', missing=True, directory=True)
    require(not fresh or not native.exists() or not os.listdir(native),
            'unowned native Arc artifacts cannot be adopted')
    for directory, name in (('/etc/sysctl.d', '90-erpc-arc-validator.conf'),
                            ('/etc/systemd/journald.conf.d', '90-erpc-arc-validator.conf')):
        context.protected(directory, missing=True, directory=True)
        file = context.protected(directory + '/' + name, missing=True)
        require(not fresh or not file.exists(), 'unowned validator host settings cannot be adopted')
    if fresh:
        managed = context.protected('/etc/erpc', missing=True, directory=True)
        require(not managed.exists() or set(os.listdir(managed)) <= {'arc-validator'},
                'dedicated validator host already contains another ERPC namespace')
        for old in ('/etc/erpc/arc/authority/owner.json', '/var/lib/arc',
                    '/etc/systemd/system/arc-execution.service',
                    '/etc/systemd/system/arc-consensus.service'):
            require(not context.path(old).exists() and not context.path(old).is_symlink(),
                    'validator requires a dedicated host; existing Arc RPC state is retained')

# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Persistently fence stale legacy NodeRun plays before native history can open.

systemd255 dash-prefix drop-ins apply to every erpc-r-*.service. The old runner
uses nonblocking flock, but a service can be delayed before reaching that lock.
Only the original manager's sealed native-owner bundle can pass this condition.
"""
import hashlib
import os
from pathlib import Path
import re
from native_files import atomic,encoded,json_value,read,require,root_directory,sync_directory,sync_file
from native_entrypoint import runtime_command
import native_helpers as helpers
import native_migration_runs as runs
import native_migration_retire as retirement

DIRECTORY=Path('/etc/systemd/system/erpc-r-.service.d')
DROPIN=DIRECTORY/'90-erpc-native-owner.conf'
RECEIPT='run-guard.json'


def definition(revision):
    require(isinstance(revision,str) and re.fullmatch('[a-f0-9]{64}',revision),'invalid original helper revision')
    return ('[Service]\nExecCondition=+'+runtime_command(helpers.RELEASES/revision/'native_runtime_control.py')+' migration-run-condition %n\n').encode()


def expected(operation):
    value=json_value(read(retirement.STORE/'helper-revision.json'))
    binding=hashlib.sha256(encoded(operation.binding)).hexdigest()
    require(set(value)=={'binding_sha256','revision'} and value['binding_sha256']==binding,'original helper receipt differs')
    helpers.verify(value['revision'])
    raw=definition(value['revision'])
    return {'binding_sha256':binding,'revision':value['revision'],'sha256':hashlib.sha256(raw).hexdigest()},raw


def namespace():
    root_directory(DIRECTORY.parent)
    if DIRECTORY.exists() or DIRECTORY.is_symlink():
        root_directory(DIRECTORY)
        require(DIRECTORY.lstat().st_mode&0o7777==0o755,'managed-run guard directory differs')
        for path in DIRECTORY.iterdir():
            require(path==DROPIN or re.fullmatch(r'\.erpc-[a-f0-9]{32}',path.name),'unknown managed-run override must be preserved')
            read(path)


def own_unit():
    source=retirement.SOURCE;run=source.parent.parent
    if source.name!='node' or source.parent.name!='bundle' or run.parent!=retirement.RUNS:return None
    if re.fullmatch('r-[a-z0-9-]{1,62}',run.name) is None:return None
    path=retirement.process.PROC/'self/cgroup'
    raw=retirement.process.bounded(path,16384).decode('ascii')
    unit='erpc-'+run.name+'.service'
    return unit if raw.strip()=='0::/system.slice/'+unit or raw.strip().startswith('0::/system.slice/'+unit+'/') else None


def other_runs_idle(run):
    return runs.other_runs_idle(run,own_unit())


def install(operation):
    operation.saved();other_runs_idle(operation.run);namespace();record,raw=expected(operation)
    path=retirement.STORE/RECEIPT
    if path.exists():require(json_value(read(path))==record,'managed-run guard belongs to another migration')
    else:atomic(path,encoded(record))
    sync_file(path);sync_directory(retirement.STORE)
    root_directory(DIRECTORY,create=True,mode=0o755)
    if DROPIN.exists() or DROPIN.is_symlink():require(read(DROPIN)==raw,'owned managed-run guard was replaced')
    else:atomic(DROPIN,raw,0o644)
    sync_file(DROPIN);sync_directory(DIRECTORY);sync_directory(DIRECTORY.parent)
    operation.run(['/usr/bin/systemctl','daemon-reload'])
    # An already activated service may have passed its condition before reload.
    # Do not stop unidentified root processes or mistake our own run for one.
    other_runs_idle(operation.run)


def verify(operation):
    namespace();record,raw=expected(operation)
    require(json_value(read(retirement.STORE/RECEIPT))==record and read(DROPIN)==raw,'original managed-run fence is missing or changed')
    other_runs_idle(operation.run)
    return record


def permit(unit,run=retirement.legacy.command):
    require(isinstance(unit,str) and re.fullmatch(r'erpc-r-[a-z0-9-]{1,62}\.service',unit),'invalid managed operation unit')
    saved=json_value(read(retirement.STORE/'original.json'))
    require(set(saved)=={'schema','binding','observation','manager_uid'} and saved['schema']==1,'original migration owner missing')
    binding=retirement.scope(dict(saved['binding'],action='migration-status'))
    operation=retirement.Retirement(dict(binding,action='migration-status'),saved['manager_uid'],run)
    operation.saved(durable=False);namespace();record,raw=expected(operation)
    require(json_value(read(retirement.STORE/RECEIPT))==record and read(DROPIN)==raw,'managed-run fence is unverified')
    identifier=unit[len('erpc-'):-len('.service')];directory=retirement.RUNS/identifier
    sealed=json_value(read(directory/'sealed.json',65536))
    require(set(sealed)=={'bundle','login','group'} and type(sealed['login'])is int and sealed['login']==saved['manager_uid']
            and isinstance(sealed['bundle'],str) and re.fullmatch('[a-f0-9]{64}',sealed['bundle']), 'managed operation belongs to another login or bundle')
    label=''.join(character if character.isascii() and character.isalnum() else '_'+format(ord(character),'02x') for character in unit)
    value=json_value(run(['/usr/bin/busctl','--system','--json=short','get-property','org.freedesktop.systemd1',
        '/org/freedesktop/systemd1/unit/'+label,'org.freedesktop.systemd1.Service','ExecStartEx']).encode())
    require(isinstance(value,dict) and set(value)=={'type','data'} and value['type']=='a(sasasttttuii)'
            and isinstance(value['data'],list) and len(value['data'])==1,'managed launch definition is ambiguous')
    command=value['data'][0]
    require(isinstance(command,list) and len(command)==10 and command[0] in ('/bin/bash','/usr/bin/bash') and command[2]==[], 'managed launch executable differs')
    argv=command[1]
    require(isinstance(argv,list) and len(argv)==5 and argv[0] in ('/bin/bash','/usr/bin/bash')
            and argv[1:4]==[str(directory/'node-run.sh'),str(directory),sealed['bundle']]
            and isinstance(argv[4],str) and re.fullmatch(r'ansible/solana-native/[a-z0-9-]+\.yml',argv[4]),
            'legacy or foreign plays cannot run after original migration retirement')
    inventory=json_value(read(directory/'bundle/inventory.yml',262144))
    require(isinstance(inventory,dict) and set(inventory)=={'all'} and set(inventory['all'])=={'hosts'}
            and set(inventory['all']['hosts'])=={binding['contract']['name']},'managed inventory owner differs')
    host=inventory['all']['hosts'][binding['contract']['name']]
    require(isinstance(host,dict) and set(host)=={'ansible_connection','solana_native_loader','solana_native_request'}
            and host['ansible_connection']=='local','managed local execution scope differs')
    request=host['solana_native_request'];require(isinstance(request,dict),'managed native request missing')
    if request.get('action')=='preflight':
        require(set(request)=={'action','role','network','volumes'} and request['volumes']==binding['contract']['volumes']
                and request['network']==binding['contract']['network']
                and request['role']==('rpc' if binding['contract']['profile']=='agave-native-rpc' else 'validator'), 'managed preflight owner differs')
    else:require(request.get('contract')==binding['contract'],'managed native owner differs')
    return True

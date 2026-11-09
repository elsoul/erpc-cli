#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual SSH inspection body; inert NSS/PID1, real public temporary files only."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[2] / 'erpc-ssh/src/solana_legacy_inspect.py'
PROGRAM = sys.argv.pop(1) if len(sys.argv) > 1 else SOURCE.read_text()
spec = importlib.util.spec_from_file_location('legacy', SOURCE)
legacy = importlib.util.module_from_spec(spec); spec.loader.exec_module(legacy)
MACHINE = b'11111111111111111111111111111111\n'
FW_PATH=SOURCE.parents[2]/'erpc-ops/templates/rpc-firewall.py'
fw_spec=importlib.util.spec_from_file_location('migration_firewall_source',FW_PATH)
firewall=importlib.util.module_from_spec(fw_spec);fw_spec.loader.exec_module(firewall)



def request():
    return {'network': 'testnet', 'role': 'validator', 'identity_account': '2' * 44,
            'vote_account': '3' * 44, 'management_user': 'operator', 'source_sha256': 'a' * 64,
            'source_history': {'document_sha256': 'c'*64, 'highest': {'version': '4.4.0-beta.1', 'commit': 'd'*40}},
            'historical': {'uid': 1001, 'gid': 1101, 'machine_id_sha256': hashlib.sha256(MACHINE.strip()).hexdigest(),
                           'source': dict.fromkeys(('passwd', 'group', 'machine_id'), 'b' * 64)}}


def script(voting=True):
    vote = '--vote-account ' + '3' * 44 if voting else '--no-voting'
    return ('#!/bin/bash\nexec agave-validator \\\n--identity /home/solv/identity.json \\\n' + vote + ' \\\n--accounts /mnt/accounts \\\n--ledger /mnt/ledger \\\n--snapshots /mnt/snapshot \\\n--expected-genesis-hash ' + legacy.GENESIS['testnet'] + ' \\\n--entrypoint entrypoint.testnet.solana.com:8001 \\\n--known-validator ' + '4' * 44 + ' \\\n--log /home/solv/solana-validator.log \\\n--dynamic-port-range 8000-8030 \\\n--rpc-port 8899 \\\n--rpc-bind-address 127.0.0.1 \\\n--no-xdp\n').encode()


MODEL = r'''
import os,pwd,grp,subprocess,types,stat,shutil
from pathlib import Path
ROOT_FIXTURE=Path(FIXTURE)
SCENARIO=CASE
# Use physical syscalls: pathlib.lstat may delegate back to the patched stat.
real_lstat=os.lstat; real_stat=os.stat; real_fstat=os.fstat; real_open=os.open; real_readlink=os.readlink

def modeled(info,path=None):
    values={name:getattr(info,name) for name in dir(info) if name.startswith('st_')}
    values['st_uid']=1001 if path and str(path).endswith('home/solv/start-validator.sh') else 0
    if SCENARIO=='foreign-owner' and path and str(path).endswith('start-validator.sh'): values['st_uid']=2002
    if path==ROOT_FIXTURE/'proc/1234/exe' and SCENARIO.startswith('cargo-'):
        values['st_uid']=2002 if SCENARIO=='cargo-foreign-owner' else 1001
        if SCENARIO=='cargo-no-link':values['st_nlink']=0
    if path and path in ROOT_FIXTURE.parents: values['st_mode'] &= ~0o022
    if path and path.parent==ROOT_FIXTURE/'mnt' and path.name in ('accounts','ledger','snapshot'):
        number=('accounts','ledger','snapshot').index(path.name)+1
        values.update(st_uid=1001,st_gid=1101,st_dev=os.makedev(8,number))
        if SCENARIO=='volume-owner' and number==2: values['st_uid']=2002
    if path==ROOT_FIXTURE/'mnt' and SCENARIO=='copy-legacy-parent': values['st_uid']=1001
    if path:
        for index,kind in enumerate(('accounts','ledger','snapshots'),4):
            target=ROOT_FIXTURE/'mnt'/('erpc-solana-'+kind)
            if path==target or target in path.parents:
                values['st_dev']=os.makedev(8,index)
                if SCENARIO=='copy-owner' and index==4:values['st_uid']=1001
    return types.SimpleNamespace(**values)
Path.lstat=lambda p,*a,**kw: modeled(real_lstat(p,*a,**kw),p)
def current_stat(path,*a,**kw):
    info=modeled(real_stat(path,*a,**kw),path)
    if kw.get('follow_symlinks',True) and path.parent==ROOT_FIXTURE/'dev/disk/by-uuid':
        number=int(path.name[-1])
        if SCENARIO=='uuid-duplicate' and number==4:number=1
        info.st_mode=stat.S_IFBLK|0o600;info.st_rdev=os.makedev(8,number)
        if SCENARIO=='uuid-regular':info.st_mode=stat.S_IFREG|0o600
    return info
def changed_image(info, field):
    assert field in ('uid','gid','mode','nlink','ino','dev','size','mtime_ns','ctime_ns')
    setattr(info,'st_'+field,getattr(info,'st_'+field)+1)
    return info
base_stat=current_stat
def current_stat(path,*a,**kw):
    info=base_stat(path,*a,**kw)
    if path==ROOT_FIXTURE/'proc/1234/exe' and SCENARIO.startswith('cargo-final-'):
        changed_image(info,SCENARIO.removeprefix('cargo-final-'))
    return info
Path.stat=current_stat
opened={}
image_reads=0
stat_reads=0
def opening(path,flags,*a,**kw):
    global stat_reads
    path=Path(path)
    assert path.name not in ('identity.json','unstaked-identity.json','solana-validator.log'), 'inspection read private material'
    if SCENARIO in ('pid-generation','cargo-pid-generation') and path.name=='stat':
        stat_reads+=1
        if stat_reads>1:
            readfd,writefd=os.pipe()
            os.write(writefd, path.read_bytes().replace(b'98765',b'98766'));os.close(writefd)
            return readfd
    fd=real_open(path,flags,*a,**kw)
    opened[fd]=opened[kw['dir_fd']]/path if 'dir_fd' in kw else path
    return fd
os.open=opening
def inspected_fd(fd):
    global image_reads
    path=opened.get(fd)
    if path==ROOT_FIXTURE/'proc/1234/exe':
        image_reads+=1
        if image_reads==2 and SCENARIO=='cargo-bytes-change':
            image=ROOT_FIXTURE/'home/solv/agave/target/release/agave-validator'
            image.chmod(0o755)
            writer=real_open(image,os.O_WRONLY)
            try:os.write(writer,b'changed public image, never executed')
            finally:os.close(writer);image.chmod(0o555)
    info=modeled(real_fstat(fd),path)
    if path==ROOT_FIXTURE/'proc/1234/exe' and image_reads==2 and SCENARIO.startswith('cargo-open-'):
        changed_image(info,SCENARIO.removeprefix('cargo-open-'))
    return info
os.fstat=inspected_fd
def kernel_link(path,*a,**kw):
    if Path(path)==ROOT_FIXTURE/'proc/1234/exe':
        if SCENARIO=='exe-outside': return '/tmp/other/agave-validator'
        if SCENARIO=='source-built-image' or SCENARIO.startswith('cargo-'):return '/home/solv/agave/target/release/agave-validator'
        return '/home/solv/.local/share/solana/install/releases/fixture/solana-release/bin/agave-validator'
    return real_readlink(path,*a,**kw)
os.readlink=kernel_link
os.geteuid=lambda:0
runtime=pwd.struct_passwd(('solv','x',1001,1101,'','/home/solv','/bin/bash'))
manager=pwd.struct_passwd(('operator','x',1000,1000,'','/home/operator','/bin/bash'))
users=[runtime,manager]
if SCENARIO=='uid-alias': users.append(pwd.struct_passwd(('alias','x',1001,2000,'','/home/alias','/bin/bash')))
if SCENARIO=='group-shared': users.append(pwd.struct_passwd(('shared','x',2000,1101,'','/home/shared','/bin/bash')))
if SCENARIO=='uid-drift': runtime=pwd.struct_passwd(('solv','x',1002,1101,'','/home/solv','/bin/bash'));users[0]=runtime
pwd.getpwall=lambda:users
pwd.getpwnam=lambda name: next(v for v in users if v.pw_name==name)
pwd.getpwuid=lambda uid: next(v for v in users if v.pw_uid==uid)
group=grp.struct_group(('solv','x',1101,[]))
groups=[group]
if SCENARIO=='gid-alias': groups.append(grp.struct_group(('alias','x',1101,[])))
if SCENARIO=='group-member': groups[0]=grp.struct_group(('solv','x',1101,['operator']));group=groups[0]
grp.getgrall=lambda:groups
grp.getgrnam=lambda name: next(v for v in groups if v.gr_name==name)
grp.getgrgid=lambda gid: next(v for v in groups if v.gr_gid==gid)
os.environ['SUDO_USER']='solv' if SCENARIO=='runtime-login' else 'operator'
os.environ['SUDO_UID']='1001' if SCENARIO=='runtime-login' else '1000'
observations=0
shutil.disk_usage=lambda path: types.SimpleNamespace(total=2_000_000_000_000,
    free=64*1024**3 if SCENARIO=='copy-capacity' else 1_500_000_000_000)
def service(argv,**kwargs):
    global observations
    assert kwargs['stdin']==subprocess.DEVNULL and kwargs['timeout']==20
    if argv[0]=='/usr/bin/du':
        assert argv[1:5]==['-sx','--apparent-size','--block-size=1','--count-links']
        assert Path(argv[5]).parent==ROOT_FIXTURE/'mnt'
        output='1000000\t'+argv[5]+'\n'
        if SCENARIO=='copy-size-invalid':output='inert-private-marker\n'
        return types.SimpleNamespace(returncode=0,stdout=output.encode(),stderr=b'')
    if argv[0]=='/usr/bin/busctl':
        if argv[6]=='org.freedesktop.systemd1.Unit':
            values=[]
            for name in argv[7:]:
                data={'DefaultDependencies':True,'StopWhenUnneeded':False,'RefuseManualStop':False,
                    'FailureAction':'none','SuccessAction':'none','StartLimitAction':'none','JobTimeoutAction':'none',
                    'After':['network.target','basic.target','sysinit.target','system.slice'],
                    'Requires':['sysinit.target','system.slice'],'Before':['shutdown.target'],
                    'Conflicts':['shutdown.target'],'WantedBy':['multi-user.target'],'RequiresMountsFor':['/home/solv']}.get(name,[])
                if SCENARIO=='unit-stop-edge' and name=='PropagatesStopTo':data=['unrelated.service']
                if SCENARIO=='unit-failure-action' and name=='FailureAction':data='reboot'
                if SCENARIO=='unit-custom-requires' and name=='Requires':data=['unrelated.service']
                kind='b' if isinstance(data,bool) else 's' if isinstance(data,str) else 'as'
                values.append(json.dumps({'type':kind,'data':data}))
            return types.SimpleNamespace(returncode=0,stdout=('\n'.join(values)+'\n').encode(),stderr=b'')
        assert argv[:7]==['/usr/bin/busctl','--system','--json=short','get-property','org.freedesktop.systemd1',
            '/org/freedesktop/systemd1/unit/solv_2eservice','org.freedesktop.systemd1.Service']
        if argv[7]=='Environment':
            declarations={
                'Environment':('as',UNIT_ENVIRONMENT), 'EnvironmentFiles':('a(sb)',[]),
                'PassEnvironment':('as',[]), 'UnsetEnvironment':('as',[]),
                'ExecSearchPath':('as',[]), 'SupplementaryGroups':('as',[]),
                'RootDirectory':('s',''), 'RootImage':('s',''), 'PAMName':('s',''),
                'DynamicUser':('b',False), 'PrivateNetwork':('b',False),
                'PrivateUsers':('b',False), 'PrivateMounts':('b',False),
                'Restart':('s','always'), 'RestartMode':('s','normal'),
                'RestartUSec':('t',1000000), 'ExitType':('s','main'),
                'KillMode':('s','control-group'),'KillSignal':('i',15),'RestartKillSignal':('i',15),'FinalKillSignal':('i',9),
                'SendSIGKILL':('b',True),'SendSIGHUP':('b',False),'TimeoutStopUSec':('t',90000000),
                'TimeoutStopFailureMode':('s','terminate'),'WatchdogUSec':('t',0),'WatchdogSignal':('i',6)}
            if SCENARIO=='environment-injection': declarations['Environment']=('as',UNIT_ENVIRONMENT+['LD_PRELOAD=inert-private-marker'])
            if SCENARIO=='environment-path': declarations['Environment']=('as',['PATH=/tmp/unknown',UNIT_ENVIRONMENT[1]])
            if SCENARIO=='environment-file': declarations['EnvironmentFiles']=('a(sb)',[['/tmp/original.env',False]])
            if SCENARIO=='pass-environment': declarations['PassEnvironment']=('as',['LD_PRELOAD'])
            if SCENARIO=='unset-environment': declarations['UnsetEnvironment']=('as',['PATH'])
            if SCENARIO=='search-path': declarations['ExecSearchPath']=('as',['/tmp'])
            if SCENARIO=='supplementary-group': declarations['SupplementaryGroups']=('as',['other'])
            if SCENARIO=='pam-policy': declarations['PAMName']=('s','login')
            if SCENARIO=='chroot-policy': declarations['RootDirectory']=('s','/srv/other')
            if SCENARIO=='dynamic-policy': declarations['DynamicUser']=('b',True)
            if SCENARIO=='private-policy': declarations['PrivateMounts']=('b',True)
            if SCENARIO=='restart-policy': declarations['RestartMode']=('s','direct')
            if SCENARIO=='kill-mode':declarations['KillMode']=('s','process')
            if SCENARIO=='kill-signal':declarations['KillSignal']=('i',9)
            if SCENARIO=='kill-timeout':declarations['TimeoutStopUSec']=('t',1)
            if SCENARIO=='kill-hup':declarations['SendSIGHUP']=('b',True)
            if SCENARIO=='restart-type': declarations['RestartUSec']=('t',True)
            values=[json.dumps({'type':declarations[name][0],'data':declarations[name][1]}) for name in argv[7:]]
            if SCENARIO=='policy-missing': values.pop()
            return types.SimpleNamespace(returncode=0,stdout=('\n'.join(values)+'\n').encode(),stderr=b'')
        values=[]
        for name in argv[7:]:
            rows=[]
            if name=='ExecStartEx':
                rows=[['/home/solv/start-validator.sh',['/home/solv/start-validator.sh'],[],0,0,0,0,1234,0,0]]
                if SCENARIO=='loaded-command': rows[0][0]='/bin/other'
                if SCENARIO=='privileged-start': rows[0][2]=['privileged']
                if SCENARIO=='launch-pid': rows[0][7]=1235
            if name=='ExecStopPostEx' and SCENARIO=='stop-hook': rows=[['/bin/other',['/bin/other'],[],0,0,0,0,0,0,0]]
            if name=='ExecStartPreEx' and (SCENARIO in ('rpc-guard','validator-guard') or SCENARIO.startswith('rpc-current')):
                rows=[['/usr/bin/python3',['/usr/bin/python3','-I','/usr/local/lib/erpc/rpc-firewall.py','solana-rpc','guard'],['privileged'],0,0,0,0,0,0,0]]
            if name=='ExecStartPreEx' and SCENARIO.startswith('rpc-current'):
                args=list(FIREWALL_ARGUMENTS)
                if SCENARIO=='rpc-current-program':args[3]+=';raise ValueError()'
                rows.append(['/usr/bin/python3',args,['privileged'],0,0,0,0,0,0,0])
            values.append(json.dumps({'type':'a(sasasttttuii)','data':rows}))
        if SCENARIO=='wrong-bus-type': values[0]=json.dumps({'type':'s','data':'inert-private-marker'})
        if SCENARIO=='missing-bus-property': values.pop()
        return types.SimpleNamespace(returncode=0,stdout=('\n'.join(values)+'\n').encode(),stderr=b'')
    assert argv[:3]==['/usr/bin/systemctl','show','solv.service'] and len(argv)==4
    observations+=1
    values={'LoadState':'loaded','FragmentPath':'/etc/systemd/system/solv.service','DropInPaths':'','Type':'simple','User':'solv','Group':'',
            'WorkingDirectory':'/home/solv','MainPID':'1234','ActiveState':'active','SubState':'running','ControlPID':'0',
            'NeedDaemonReload':'no','InvocationID':'c'*32,'ControlGroup':'/system.slice/solv.service'}
    if SCENARIO.startswith('rpc-current'):values['DropInPaths']='/etc/systemd/system/solv.service.d/50-erpc-firewall-guard.conf'
    if SCENARIO=='drop-in': values['DropInPaths']='/etc/systemd/system/solv.service.d/foreign.conf'
    if SCENARIO=='other-unit': values['FragmentPath']='/etc/systemd/system/foreign.service'
    if SCENARIO=='service-user': values['User']='other'
    if SCENARIO=='pending-reload': values['NeedDaemonReload']='yes'
    if SCENARIO=='control-process': values['ControlPID']='1235'
    if SCENARIO=='transition': values['ActiveState']='activating'
    if SCENARIO=='forking': values['Type']='forking'
    if SCENARIO=='invocation-change' and observations>1: values['InvocationID']='d'*32
    if SCENARIO=='inactive': values.update(MainPID='0',ActiveState='inactive',SubState='dead',InvocationID='',ControlGroup='')
    return types.SimpleNamespace(returncode=0,stdout=('\n'.join(k+'='+v for k,v in values.items())+'\n').encode(),stderr=b'')
subprocess.run=service
'''


class Inspection(unittest.TestCase):
    def test_fixture_preserves_uuid_symlink_metadata_for_both_nofollow_interfaces(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve()
            links=root/'dev/disk/by-uuid';links.mkdir(parents=True)
            target=root/'dev/block-1';target.write_bytes(b'inert block-device stand-in')
            link=links/'10000000-0000-0000-0000-000000000001';link.symlink_to(target)
            model=MODEL.replace('Path(FIXTURE)','Path('+repr(str(root))+')').replace('CASE',repr('safe'))
            checks="""
link=ROOT_FIXTURE/'dev/disk/by-uuid/10000000-0000-0000-0000-000000000001'
assert stat.S_ISLNK(link.lstat().st_mode)
assert stat.S_ISLNK(link.stat(follow_symlinks=False).st_mode)
assert stat.S_ISBLK(link.stat().st_mode)
assert link.stat().st_rdev==os.makedev(8,1)
assert stat.S_ISREG(real_stat(link).st_mode)
"""
            result=subprocess.run([sys.executable,'-I','-c',model+checks],capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(target.read_bytes(),b'inert block-device stand-in')
            self.assertTrue(link.is_symlink())

    def execute(self, scenario='safe', body=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for directory in ('etc/systemd/system', 'home/solv'):
                (root / directory).mkdir(parents=True)
            unit = root / 'etc/systemd/system/solv.service'; unit.write_text('[Service]\nUser=solv\nExecStart=/home/solv/start-validator.sh\n'); unit.chmod(0o644)
            startup = root / 'home/solv/start-validator.sh'; startup.write_bytes(script(not (scenario=='rpc-guard' or scenario.startswith('rpc-current')))); startup.chmod(0o700)
            if scenario.startswith('rpc-current'):
                directory=unit.with_name('solv.service.d');directory.mkdir(mode=0o755)
                dropin=directory/'50-erpc-firewall-guard.conf';dropin.write_text(firewall.Firewall('solana-rpc').guard_config());dropin.chmod(0o644)
                if scenario=='rpc-current-writable':dropin.chmod(0o666)
                if scenario=='rpc-current-extra':(directory/'override.conf').write_text('[Service]\nUser=root\n')
                if scenario=='rpc-current-bytes':dropin.write_text('[Service]\nUser=root\n')
            machine = root / 'etc/machine-id'; machine.write_bytes(MACHINE); machine.chmod(0o644)
            process = root / 'proc/1234'; process.mkdir(parents=True)
            (process / 'stat').write_bytes(b'1234 (agave-validator) S ' + b'0 ' * 18 + b'98765\n')
            uid = 1002 if scenario == 'process-uid' else 1001
            (process / 'status').write_text('Uid: ' + ' '.join([str(uid)] * 4) + '\nGid: 1101 1101 1101 1101\n'
                + ''.join(name + ': ' + ('1' if scenario == 'process-capability' and name == 'CapEff' else '0') + '\n'
                          for name in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb')))
            (process / 'cgroup').write_text('0::/system.slice/' + ('other' if scenario == 'process-cgroup' else 'solv') + '.service\n')
            argv = startup.read_text().partition('\n')[2].replace('\\\n', ' ').split()[1:]
            if scenario == 'argv-drift': argv += ['--no-voting']
            (process / 'cmdline').write_bytes(b'\0'.join(v.encode() for v in argv) + b'\0')
            template=SOURCE.parents[1]/'../erpc-chain-solana/templates/jinja/testnet-validator/solv.service.j2'
            native_environment=[line.removeprefix('Environment=') for line in template.read_text().splitlines() if line.startswith('Environment=')]
            native_environment += ['HOME=/home/solv','USER=solv','LOGNAME=solv','SHELL=/bin/bash','PWD=/home/solv','SHLVL=0','LANG=C.UTF-8','INVOCATION_ID='+'c'*32,'SYSTEMD_EXEC_PID=1234']
            if scenario=='effective-preload':native_environment.append('LD_PRELOAD=inert-private-marker')
            if scenario=='effective-home':native_environment=[line if not line.startswith('HOME=') else 'HOME=/tmp/unknown' for line in native_environment]
            if scenario=='effective-duplicate':native_environment.append('USER=solv')
            if scenario=='effective-metrics':native_environment=[line if not line.startswith('SOLANA_METRICS_CONFIG=') else 'SOLANA_METRICS_CONFIG=inert-private-marker' for line in native_environment]
            (process/'environ').write_bytes(b'\0'.join(value.encode() for value in native_environment)+b'\0')
            binary = root / 'inert-image'; binary.write_bytes(b'inert published image, never executed'); binary.chmod(0o555)
            if scenario.startswith('cargo-') or scenario=='release-hardlink':
                published=root/'home/solv/agave/target/release/agave-validator'
                deps=published.parent/'deps';deps.mkdir(parents=True)
                binary.rename(published);binary=published
                os.link(binary,deps/'agave-validator-inert-build')
                self.assertEqual(binary.stat().st_nlink,2)
                if scenario=='cargo-writable':binary.chmod(0o577)
                if scenario=='cargo-setuid':binary.chmod(0o4555)
            (process / 'exe').symlink_to(binary)
            (process / 'ns').mkdir(); observer = root / 'proc/self/ns'; observer.mkdir(parents=True)
            for namespace in ('mnt', 'pid', 'user', 'net'):
                original = observer / namespace; original.write_text('inert kernel namespace')
                if scenario == 'process-namespace' and namespace == 'mnt': (process / 'ns' / namespace).write_text('other namespace')
                else: os.link(original, process / 'ns' / namespace)
            uuid_dir=root/'dev/disk/by-uuid';uuid_dir.mkdir(parents=True)
            entries=['1 0 8:0 / / rw - ext4 /dev/inert-root rw']
            for number,name in enumerate(('accounts','ledger','snapshot'),1):
                (root/'mnt'/name).mkdir(parents=True,mode=0o700)
                block=root/'dev'/('block-'+str(number));block.write_bytes(b'inert device')
                identifier='10000000-0000-0000-0000-00000000000'+str(number)
                (uuid_dir/identifier).symlink_to(block)
                mountroot='/subdirectory' if scenario=='volume-bind' and number==1 else '/'
                flags='ro' if scenario=='volume-readonly' and number==1 else 'rw'
                entries.append(f'{number+1} 1 8:{number} {mountroot} /mnt/{name} {flags} - ext4 /dev/inert-{number} {flags}')
            if scenario=='volume-alias':entries.append('5 1 8:1 / /mnt/alias rw - ext4 /dev/inert-1 rw')
            if scenario=='volume-nested':entries.append('5 2 8:4 / /mnt/accounts/foreign rw - ext4 /dev/inert-4 rw')
            if scenario=='uuid-duplicate':(uuid_dir/'10000000-0000-0000-0000-000000000004').symlink_to(root/'dev/block-1')
            if scenario=='uuid-missing':(uuid_dir/'10000000-0000-0000-0000-000000000001').unlink()
            targets={}
            if scenario.startswith('copy-'):
                for number,kind in enumerate(('accounts','ledger','snapshots'),4):
                    target=root/'mnt'/('erpc-solana-'+kind);target.mkdir(mode=0o700)
                    block=root/'dev'/('block-'+str(number));block.write_bytes(b'inert target block')
                    identifier='10000000-0000-0000-0000-00000000000'+str(number)
                    (uuid_dir/identifier).symlink_to(block);targets[kind]=identifier
                    flags='ro' if scenario=='copy-readonly' and number==4 else 'rw'
                    entries.append(f'{number+1} 1 8:{number} / /mnt/erpc-solana-{kind} {flags} - ext4 /dev/inert-{number} {flags}')
                    if number==4:
                        if scenario=='copy-nonempty':(target/'existing').write_text('retain original target content')
                        if scenario=='copy-writable':target.chmod(0o777)
                        if scenario in ('copy-recovery','copy-recovered-data'):
                            recovery=target/'lost+found';recovery.mkdir(mode=0o700)
                            if scenario=='copy-recovered-data':(recovery/'original').write_text('retain recovered data')
                if scenario=='copy-reuses-source':targets['accounts']='10000000-0000-0000-0000-000000000001'
                if scenario=='copy-wrong-uuid':targets['accounts']=targets['ledger'];targets['ledger']='10000000-0000-0000-0000-000000000004'
                if scenario=='copy-nested':entries.append('20 5 8:7 / /mnt/erpc-solana-accounts/foreign rw - ext4 /dev/inert-7 rw')
                if scenario=='copy-alias':entries.append('20 1 8:4 / /mnt/alias rw - ext4 /dev/inert-4 rw')
            (root/'proc/self/mountinfo').write_text('\n'.join(entries)+'\n')
            if scenario == 'wrong-machine': machine.write_bytes(b'2' * 32 + b'\n')
            if scenario == 'write-file': startup.chmod(0o722)
            if scenario == 'write-home': startup.parent.chmod(0o777)
            if scenario == 'hardlink': os.link(startup, root / 'alias')
            if scenario == 'symlink': startup.rename(root / 'outside'); startup.symlink_to(root / 'outside')
            if scenario == 'shell-expression': startup.write_bytes(script() + b'$(touch /tmp/not-permitted)\n')
            before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file() and not p.is_symlink()}
            code = MODEL.replace('Path(FIXTURE)', 'Path(' + repr(str(root)) + ')').replace('CASE', repr(scenario)) + PROGRAM.replace("ROOT = Path('/')", 'ROOT = Path(' + repr(str(root)) + ')')
            template=SOURCE.parents[2]/'erpc-chain-solana/templates/jinja/testnet-validator/solv.service.j2'
            declarations=[line[len('Environment='):] for line in template.read_text().splitlines() if line.startswith('Environment=')]
            code='UNIT_ENVIRONMENT='+repr(declarations)+'\nFIREWALL_ARGUMENTS='+repr(firewall.entrypoint_arguments('solana-rpc','guard'))+'\n'+code
            selected = request()
            if targets:selected['target_volumes']=targets
            if scenario=='rpc-guard' or scenario.startswith('rpc-current'): selected.update(role='rpc', vote_account=None)
            result = subprocess.run([sys.executable, '-I', '-c', code], input=body or json.dumps(selected).encode(), capture_output=True, timeout=10)
            after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file() and not p.is_symlink()}
            if scenario=='cargo-bytes-change':
                changed={name for name in before if before[name]!=after[name]}
                self.assertEqual(changed,{'home/solv/agave/target/release/agave-validator',
                    'home/solv/agave/target/release/deps/agave-validator-inert-build'})
            else:self.assertEqual(before, after, 'inspection modified its source')
            if result.returncode != 0:
                self.assertEqual(result.stderr, b'Legacy Solv public inspection failed; preserve the existing configuration\n')
            return result

    def test_current_common_guard_is_source_pinned_and_coexists_with_original_unit_guard(self):
        self.assertEqual(hashlib.sha256(firewall.entrypoint_arguments('solana-rpc','guard')[3].encode()).hexdigest(),legacy.FIREWALL_PROGRAM)
        for text in (firewall.Firewall('solana-rpc').guard_config(),firewall.Firewall('solana-rpc').legacy_guard_config()):
            self.assertIn(hashlib.sha256(text.encode()).hexdigest(),legacy.FIREWALL_DROPINS)
        result=self.execute('rpc-current');self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(set(json.loads(result.stdout)['dropins']),{'50-erpc-firewall-guard.conf'})
        for scenario in ('rpc-current-program','rpc-current-writable','rpc-current-extra','rpc-current-bytes'):
            with self.subTest(scenario=scenario):
                result=self.execute(scenario);self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')

    def test_actual_entrypoint_matches_history_without_opening_a_key_or_changing_service(self):
        result = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertTrue(value['historical_account_matches'])
        self.assertTrue(value['read_only'])
        self.assertEqual(value['original_source_history'], request()['source_history'])
        self.assertFalse(value['execution_authorized'])
        self.assertEqual(value['original']['uid'], 1001)
        self.assertEqual(value['startup']['mode'], 'validator')
        self.assertEqual(value['startup']['script_sha256'], hashlib.sha256(script()).hexdigest())
        self.assertIn('storage-and-voting-history', value['remaining_checks'])
        self.assertFalse(value['service']['process']['native_source_verified'])
        self.assertEqual(value['service']['process']['start_ticks'], 98765)
        self.assertEqual(value['storage']['ledger']['uuid'],'10000000-0000-0000-0000-000000000002')
        self.assertNotIn(MACHINE.strip(), result.stdout)

    def test_effective_process_environment_and_loaded_stop_dependencies_are_bound_without_values(self):
        positive=self.execute();self.assertEqual(positive.returncode,0)
        value=json.loads(positive.stdout)
        self.assertRegex(value['service']['process']['effective_environment_sha256'],'^[a-f0-9]{64}$')
        self.assertRegex(value['service']['dependencies_sha256'],'^[a-f0-9]{64}$')
        self.assertNotIn('SOLANA_METRICS_CONFIG',positive.stdout.decode())
        for case in ('effective-preload','effective-home','effective-duplicate','effective-metrics',
                     'unit-stop-edge','unit-failure-action','unit-custom-requires'):
            with self.subTest(case=case):
                result=self.execute(case);self.assertNotEqual(result.returncode,0)
                self.assertEqual(result.stdout,b'');self.assertNotIn(b'inert-private-marker',result.stderr)

    def test_current_binary_matches_only_separately_supplied_original_build_evidence(self):
        body=request();body['artifact_evidence']={'document_sha256':'e'*64,'network':'testnet',
            'source':dict(body['source_history']['highest'],cargo_lock_sha256='f'*64,rust='1.98.1',rust_manifest_sha256='a'*64),
            'executable_sha256':hashlib.sha256(b'inert published image, never executed').hexdigest(),
            'executable_bytes':len(b'inert published image, never executed')}
        positive=self.execute(body=json.dumps(body).encode());self.assertEqual(positive.returncode,0)
        observed=json.loads(positive.stdout)
        self.assertTrue(observed['service']['process']['artifact_evidence_matches'])
        self.assertEqual(observed['original_build_evidence'],body['artifact_evidence'])
        self.assertFalse(observed['execution_authorized']);self.assertFalse(observed['service']['process']['native_source_verified'])
        for field,value in [('executable_sha256','b'*64),('executable_bytes',1),('network','mainnet')]:
            changed=json.loads(json.dumps(body));changed['artifact_evidence'][field]=value
            result=self.execute(body=json.dumps(changed).encode());self.assertNotEqual(result.returncode,0)
            self.assertEqual(result.stdout,b'')
        absent=self.execute();self.assertFalse(json.loads(absent.stdout)['service']['process']['artifact_evidence_matches'])
        built=self.execute('source-built-image',body=json.dumps(body).encode());self.assertEqual(built.returncode,0)
        self.assertEqual(json.loads(built.stdout)['service']['process']['source_layout'],'managed-agave-build')
        self.assertTrue(json.loads(built.stdout)['service']['process']['artifact_evidence_matches'])

    def cargo_evidence(self):
        body=request()
        body['artifact_evidence']={'document_sha256':'e'*64,'network':'testnet',
            'source':dict(body['source_history']['highest'],cargo_lock_sha256='f'*64,
                          rust='1.98.1',rust_manifest_sha256='a'*64),
            'executable_sha256':hashlib.sha256(b'inert published image, never executed').hexdigest(),
            'executable_bytes':len(b'inert published image, never executed')}
        return body

    def test_linux_cargo_deps_hardlink_is_observed_with_independent_artifact_evidence(self):
        result=self.execute('cargo-hardlink',body=json.dumps(self.cargo_evidence()).encode())
        self.assertEqual(result.returncode,0,result.stderr)
        value=json.loads(result.stdout);process=value['service']['process']
        self.assertEqual(process['source_layout'],'managed-agave-build')
        self.assertTrue(process['artifact_evidence_matches'])
        self.assertEqual(process['image_sha256'],self.cargo_evidence()['artifact_evidence']['executable_sha256'])
        self.assertEqual(process['image_bytes'],self.cargo_evidence()['artifact_evidence']['executable_bytes'])
        self.assertFalse(value['execution_authorized']);self.assertFalse(process['native_source_verified'])
        # Absence of independently retained evidence still grants no authority.
        absent=self.execute('cargo-hardlink');self.assertEqual(absent.returncode,0)
        self.assertFalse(json.loads(absent.stdout)['service']['process']['artifact_evidence_matches'])

    def test_cargo_alias_does_not_relax_image_evidence_or_release_layout(self):
        for field,value in [('executable_sha256','b'*64),('executable_bytes',1),('network','mainnet')]:
            body=self.cargo_evidence();body['artifact_evidence'][field]=value
            with self.subTest(field=field):
                result=self.execute('cargo-hardlink',body=json.dumps(body).encode())
                self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
        for field,value in [('version','9.0.0'),('commit','c'*40)]:
            body=self.cargo_evidence();body['artifact_evidence']['source'][field]=value
            with self.subTest(source=field):
                result=self.execute('cargo-hardlink',body=json.dumps(body).encode())
                self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
        for scenario in ('cargo-foreign-owner','cargo-no-link','cargo-writable','cargo-setuid',
                         'cargo-pid-generation','release-hardlink','cargo-bytes-change'):
            with self.subTest(scenario=scenario):
                result=self.execute(scenario,body=json.dumps(self.cargo_evidence()).encode())
                self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')

    def test_opened_and_final_cargo_image_metadata_remain_identical(self):
        for point in ('open','final'):
            for field in ('uid','gid','mode','nlink','ino','dev','size','mtime_ns','ctime_ns'):
                with self.subTest(point=point,field=field):
                    result=self.execute('cargo-'+point+'-'+field,body=json.dumps(self.cargo_evidence()).encode())
                    self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')

    def test_original_account_machine_and_management_login_drift_refuse_without_mutation(self):
        for case in ('uid-alias', 'uid-drift', 'gid-alias', 'group-shared', 'group-member', 'wrong-machine', 'runtime-login'):
            with self.subTest(case=case):
                result = self.execute(case)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b'')
                self.assertEqual(result.stderr, b'Legacy Solv public inspection failed; preserve the existing configuration\n')

    def test_hostile_public_files_and_unexpected_loaded_units_are_not_adopted(self):
        for case in ('write-file', 'write-home', 'hardlink', 'symlink', 'foreign-owner', 'drop-in', 'other-unit', 'service-user', 'shell-expression'):
            with self.subTest(case=case):
                result = self.execute(case)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b'')

    def test_actual_readonly_projection_binds_the_approved_public_settings(self):
        first = self.execute(); self.assertEqual(first.returncode, 0, first.stderr.decode())
        value = json.loads(first.stdout)
        self.assertEqual(value['settings_sha256'], legacy.settings_digest(value['settings']))
        req = request(); req['settings_sha256'] = value['settings_sha256']
        accepted = self.execute(body=json.dumps(req).encode())
        self.assertEqual(accepted.returncode, 0, accepted.stderr.decode())
        req['settings_sha256'] = '0' * 64
        refused = self.execute(body=json.dumps(req).encode())
        self.assertNotEqual(refused.returncode, 0); self.assertEqual(refused.stdout, b'')

    def test_unsupported_shell_features_and_flag_values_never_echo_their_contents(self):
        for change in (b'--geyser-plugin-config inert-private-marker', b'--staked-nodes-overrides overrides.yml',
                       b'; touch /tmp/inert-private-marker', b'--identity inert-private-marker',
                       b'--log inert-private-marker', b'--entrypoint inert-private-marker', b'--rpc-port 9999'):
            with self.subTest(change=change):
                with self.assertRaises(ValueError) as error: legacy.startup(script() + change, request())
                self.assertNotIn('inert-private-marker', str(error.exception))

    def test_roles_and_networks_cannot_be_reinterpreted(self):
        req = request(); req['role'] = 'rpc'; req['vote_account'] = None
        with self.assertRaises(ValueError): legacy.startup(script(), req)
        self.assertEqual(legacy.startup(script(False), req)['mode'], 'rpc')
        req = request(); self.assertEqual(legacy.startup(script(False), req)['mode'], 'sync')
        req['network'] = 'mainnet'
        with self.assertRaises(ValueError): legacy.startup(script(), req)
        req = request(); req['vote_account'] = '4' * 44
        with self.assertRaises(ValueError): legacy.startup(script(), req)

    def test_request_shape_bool_ids_duplicates_and_extra_fields_are_refused(self):
        for mutate in (lambda v:v.update(extra='inert-private-marker'), lambda v:v['historical'].update(uid=True),
                       lambda v:v.update(management_user='solv'), lambda v:v.update(source_sha256='inert-private-marker'),
                       lambda v:v['source_history']['highest'].update(version=True),
                       lambda v:v['source_history']['highest'].update(commit='inert-private-marker'),
                       lambda v:v['source_history'].update(document_sha256='inert-private-marker')):
            req = request(); mutate(req)
            result = self.execute(body=json.dumps(req).encode())
            self.assertNotEqual(result.returncode, 0); self.assertEqual(result.stdout, b'')
            self.assertNotIn(b'inert-private-marker', result.stderr)
        result = self.execute(body=b'{"network":"testnet","network":"mainnet"}')
        self.assertNotEqual(result.returncode, 0); self.assertEqual(result.stdout, b'')

    def test_loaded_commands_and_kernel_process_must_match_the_same_original_invocation(self):
        for case in ('loaded-command', 'privileged-start', 'launch-pid', 'forking', 'stop-hook', 'validator-guard', 'wrong-bus-type', 'missing-bus-property',
                     'pending-reload', 'control-process', 'transition', 'invocation-change', 'process-uid',
                     'process-capability', 'process-cgroup', 'argv-drift', 'process-namespace', 'exe-outside', 'pid-generation'):
            with self.subTest(case=case):
                result = self.execute(case)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b'')
        value = json.loads(self.execute('inactive').stdout)
        self.assertIsNone(value['service']['process'])
        self.assertIn('stopped-writer-reconciliation', value['remaining_checks'])
        self.assertFalse(value['execution_authorized'])

    def test_loaded_policy_rejects_environment_and_execution_substitution_without_exposing_values(self):
        for case in ('environment-injection','environment-path','environment-file','pass-environment','unset-environment',
                     'search-path','supplementary-group','pam-policy','chroot-policy','dynamic-policy','private-policy',
                     'restart-policy','restart-type','policy-missing','kill-mode','kill-signal','kill-timeout','kill-hup'):
            with self.subTest(case=case):
                result=self.execute(case)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(result.stdout,b'')
                self.assertNotIn(b'inert-private-marker',result.stderr)
        result=self.execute()
        value=json.loads(result.stdout)
        self.assertEqual(len(value['service']['execution_policy_sha256']),64)
        self.assertIn('effective-environment-compatibility',value['remaining_checks'])
        self.assertNotIn(b'SOLANA_METRICS_CONFIG',result.stdout)

    def test_environment_qualification_matches_the_actual_carried_units(self):
        for network,role in [('mainnet','mainnet-validator'),('mainnet','mainnet-rpc'),('testnet','testnet-validator')]:
            path=SOURCE.parents[2]/'erpc-chain-solana/templates/jinja'/role/'solv.service.j2'
            declarations=sorted(line[len('Environment='):] for line in path.read_text().splitlines() if line.startswith('Environment='))
            self.assertEqual(len(declarations),2)
            self.assertEqual(legacy.digest(json.dumps(declarations,separators=(',',':')).encode()),legacy.ENVIRONMENT_SHA256[network])
        value = json.loads(self.execute('rpc-guard').stdout)
        self.assertEqual(value['startup']['mode'], 'rpc')
        self.assertFalse(value['execution_authorized'])

    def test_original_volumes_require_distinct_uuid_mounts_without_alias_or_owner_substitution(self):
        for case in ('volume-owner','volume-bind','volume-readonly','volume-alias','volume-nested',
                     'uuid-duplicate','uuid-missing','uuid-regular'):
            with self.subTest(case=case):
                result=self.execute(case)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(result.stdout,b'')

    def test_copy_preflight_reports_separate_empty_capacity_without_touching_originals(self):
        for case in ('copy-safe','copy-recovery','copy-legacy-parent'):
            with self.subTest(case=case):
                result=self.execute(case)
                self.assertEqual(result.returncode,0,result.stderr)
                value=json.loads(result.stdout)['copy_preflight']
                self.assertTrue(value['requires_stopped_recheck'] and value['source_retained'])
                self.assertFalse(value['copy_authorized'])
                self.assertEqual(value['parent_ownership_transition_required'],case=='copy-legacy-parent')
                self.assertEqual(value['targets']['ledger']['logical_source_bytes'],1000000)
                self.assertEqual(value['targets']['ledger']['required_free_bytes'],1000000+64*1024**3)

    def test_copy_preflight_refuses_original_reuse_and_occupied_or_unqualified_targets(self):
        for case in ('copy-reuses-source','copy-wrong-uuid','copy-nonempty','copy-writable','copy-recovered-data',
                     'copy-readonly','copy-nested','copy-alias','copy-owner','copy-capacity','copy-size-invalid'):
            with self.subTest(case=case):
                result=self.execute(case)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(result.stdout,b'')
                self.assertNotIn(b'inert-private-marker',result.stderr)


if __name__ == '__main__': unittest.main()

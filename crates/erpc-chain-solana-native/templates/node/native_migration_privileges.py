# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original Solv login/privilege retirement, never UID/home/data reassignment.

Only the qualified managed sudo grant and ordinary Ubuntu SSH include layout
are supported. Unknown policy remains an explicit recovery boundary. The caller
holds the host-operation lock, authenticates original retirement and checks the
entire original UID for writers. This module never restores the legacy login.
"""
import grp
import hashlib
import os
from pathlib import Path
import pwd
import re
import shlex
import subprocess
from native_files import atomic, encoded, json_value, read, require, root_directory, sync_directory, sync_file

ROOT = Path('/')
STORE = Path('/var/lib/erpc-solana-migration/privileges')
ROOT_UID = 0
SUDO_GRANT = b'solv ALL=(ALL) NOPASSWD:ALL\n'
SSH_DENIAL = b'DenyUsers solv\n'
SSH_FILE = '/etc/ssh/sshd_config.d/00-erpc-solv-retired.conf'
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'}


def path(name):
    require(name.startswith('/') and '..' not in Path(name).parts,'invalid fixed retirement path')
    return ROOT/name.lstrip('/')


def sha(raw): return hashlib.sha256(raw).hexdigest()


def command(argv):
    result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          check=False,timeout=30,env=ENV,close_fds=True)
    require(len(result.stdout)<=65536 and len(result.stderr)<=65536,'retirement observation exceeds its bound')
    return result


def binding(value):
    require(isinstance(value,dict) and set(value)=={'intent','source_sha256','uid','gid','manager','manager_uid','ssh_port'}
            and isinstance(value['intent'],str) and re.fullmatch('[a-f0-9]{32}',value['intent'])
            and isinstance(value['source_sha256'],str) and re.fullmatch('[a-f0-9]{64}',value['source_sha256'])
            and all(type(value[name])is int and 0<value[name]<2**31 for name in ('uid','gid','manager_uid'))
            and value['uid']!=value['manager_uid'] and type(value['ssh_port'])is int and 1<=value['ssh_port']<=65535
            and isinstance(value['manager'],str) and re.fullmatch('[a-z][a-z0-9_-]{0,31}',value['manager'])
            and value['manager'] not in ('solv','root'),'invalid original privilege-retirement scope')
    return value


def original_accounts(value,partial=False):
    users,groups=pwd.getpwall(),grp.getgrall()
    require(len(users)<=100000 and len(groups)<=100000,'NSS retirement namespace exceeds its bound')
    uid,gid=value['uid'],value['gid'];user=pwd.getpwnam('solv');group=grp.getgrnam('solv')
    require(user.pw_uid==uid and user.pw_gid==gid and user.pw_dir=='/home/solv'
            and user.pw_shell in (('/bin/bash','/usr/sbin/nologin') if partial else ('/bin/bash',))
            and pwd.getpwuid(uid)==user and len([entry for entry in users if entry.pw_uid==uid or entry.pw_name=='solv'])==1
            and group.gr_gid==gid and grp.getgrgid(gid)==group and set(group.gr_mem)<={'solv'}
            and len([entry for entry in groups if entry.gr_gid==gid or entry.gr_name=='solv'])==1
            and not any(entry.pw_name!='solv' and entry.pw_gid==gid for entry in users),
            'original Solv account/group was reassigned or has an unsupported shell')
    sudo=grp.getgrnam('sudo')
    require(grp.getgrgid(sudo.gr_gid)==sudo and len([entry for entry in groups if entry.gr_gid==sudo.gr_gid or entry.gr_name=='sudo'])==1,
            'administrative group is ambiguous')
    memberships=set(os.getgrouplist('solv',gid))
    enumerated={entry.gr_gid for entry in groups if 'solv' in entry.gr_mem}|{gid}
    require(memberships==enumerated and memberships<={gid,sudo.gr_gid},'Solv has unqualified supplementary privileges')
    manager=pwd.getpwnam(value['manager'])
    require(manager.pw_uid==value['manager_uid'] and manager.pw_gid!=gid and manager.pw_shell not in ('/usr/sbin/nologin','/bin/false')
            and pwd.getpwuid(manager.pw_uid)==manager
            and len([entry for entry in users if entry.pw_uid==manager.pw_uid or entry.pw_name==manager.pw_name])==1,
            'separate management identity changed')
    return {'shell':user.pw_shell,'groups':sorted(memberships),
            'manager':{'uid':manager.pw_uid,'gid':manager.pw_gid,'home':manager.pw_dir,'shell':manager.pw_shell}}


def protected(name,maximum=262144):
    selected=path(name);root_directory(selected.parent)
    return read(selected,maximum,ROOT_UID)


def ssh_sources():
    directory=path('/etc/ssh/sshd_config.d');root_directory(directory)
    selected=['/etc/ssh/sshd_config']
    for entry in sorted(directory.iterdir()):
        require(len(selected)<128,'SSH retirement namespace exceeds its bound')
        if entry.name.endswith('.conf') and str(entry)!=str(path(SSH_FILE)):
            selected.append('/etc/ssh/sshd_config.d/'+entry.name)
    hashes={}
    for name in selected:
        raw=protected(name);hashes[name]=sha(raw)
        lines=[]
        for line in raw.decode().splitlines():
            words=shlex.split(line,comments=True)
            if words:lines.append(words)
        if name=='/etc/ssh/sshd_config':
            require(lines and [word.lower() for word in lines[0]]==['include','/etc/ssh/sshd_config.d/*.conf'],
                    'SSH requires its qualified leading Ubuntu include directory')
            lines=lines[1:]
        require(all(words[0].lower() not in ('include','match','denyusers','allowusers','denygroups','allowgroups') for words in lines),
                'custom SSH admission policy needs separate migration qualification')
    return hashes


def sudo_source():
    raw=protected('/etc/sudoers')
    rows=raw.splitlines(keepends=True);positions=[index for index,line in enumerate(rows) if line==SUDO_GRANT]
    require(len(positions)==1 and (positions[0]==0 or not rows[positions[0]-1].rstrip().endswith(b'\\')),
            'the original exact managed Solv sudo grant is absent or ambiguous')
    for line in raw.decode().splitlines():
        line=line.strip()
        if line.startswith(('@include','#include')):
            require(line in ('@includedir /etc/sudoers.d','#includedir /etc/sudoers.d'),
                    'custom sudo include needs separate qualification')
    # LDAP/custom policy plugins cannot be retired by editing this local grant.
    for name in ('/etc/sudo.conf','/etc/nsswitch.conf'):
        if not path(name).exists():continue
        for line in protected(name).decode().splitlines():
            words=shlex.split(line,comments=True)
            if not words:continue
            if name.endswith('sudo.conf'):
                require(words in (['Plugin','sudoers_policy','sudoers.so'],['Plugin','sudoers_io','sudoers.so'],
                                  ['Plugin','sudoers_audit','sudoers.so']), 'custom sudo plugin policy is unsupported')
            elif words[0]=='sudoers:':require(words==['sudoers:','files'],'remote sudo authorization is unsupported')
    mode=path('/etc/sudoers').lstat().st_mode&0o7777
    require(mode in (0o400,0o440),'original sudoers policy has an unsupported mode')
    return raw,b''.join(row for index,row in enumerate(rows) if index!=positions[0]),mode


class Revocation:
    def __init__(self,scope,authorize,quiescent,run=command):
        self.scope=binding(scope);self.authorize=authorize;self.quiescent=quiescent;self.run=run
    def call(self,argv,success=True):
        result=self.run(argv)
        require(len(result.stdout)<=65536 and len(result.stderr)<=65536,'retirement response exceeds its bound')
        require(not success or result.returncode==0,'original privilege retirement command failed; output withheld')
        return result
    def namespace(self):
        root_directory(STORE,create=True,mode=0o700)
        require(STORE.lstat().st_mode&0o7777==0o700,'privilege retirement store is not private')
        entries=list(STORE.iterdir())
        require(len(entries)<=256,'privilege retirement namespace exceeds its bound')
        has_receipt=any(entry.name=='original.json' for entry in entries)
        for entry in entries:
            require(entry.name in (('original.json','sudoers.original','sudoers.candidate') if has_receipt else ('sudoers.original',))
                    or re.fullmatch(r'\.erpc-[a-f0-9]{32}',entry.name),'unknown privilege retirement state cannot be adopted')
            read(entry,262144,ROOT_UID)
    def saved(self):
        self.namespace()
        value=json_value(read(STORE/'original.json',owner=ROOT_UID))
        require(isinstance(value,dict) and set(value)=={'format','binding','manager','ssh','sudo_sha256','candidate_sha256','sudo_mode','phase'}
                and type(value['format'])is int and value['format']==1 and value['binding']==self.scope
                and value['phase'] in ('reserved','ssh-denied','revoked'),'privilege retirement belongs to another original scope')
        sync_file(STORE/'original.json',ROOT_UID);sync_directory(STORE)
        return value
    def put(self,value): atomic(STORE/'original.json',encoded(value))
    def ssh_effective(self,retired):
        self.call(['/usr/sbin/sshd','-t'])
        raw=self.call(['/usr/sbin/sshd','-T']).stdout.decode();values={}
        for line in raw.splitlines():
            name,separator,value=line.partition(' ')
            if name in ('denyusers','pubkeyauthentication','port'):
                require(separator,'invalid effective SSH policy');values.setdefault(name,[]).append(value)
        require(values.get('pubkeyauthentication')==['yes'] and str(self.scope['ssh_port']) in values.get('port',[])
                and values.get('denyusers',[])==(['solv'] if retired else []),
                'effective SSH policy would lose the separate manager or retain the old login')
    def account_status(self):
        password=self.call(['/usr/bin/passwd','-S','solv']).stdout.decode().split()
        require(len(password)>=2 and password[0]=='solv' and password[1] in ('P','L','NP'),'public password lock state is unknown')
        rows=[line.partition(':')[2].strip() for line in self.call(['/usr/bin/chage','--list','--iso8601','solv']).stdout.decode().splitlines()
              if line.partition(':')[0].strip()=='Account expires']
        require(len(rows)==1,'public account expiration state is unknown')
        return password[1],rows[0]
    def manager(self,expected):
        require(original_accounts(self.scope,partial=True)['manager']==expected,'separate management account changed')
        self.call(['/usr/bin/sudo','-n','-u',self.scope['manager'],'--','/usr/bin/sudo','-n','--','/usr/bin/true'])
    def verify(self):
        self.authorize(self.scope);value=self.saved();self.manager(value['manager'])
        current=original_accounts(self.scope,partial=True)
        require(current['shell']=='/usr/sbin/nologin' and current['groups']==[self.scope['gid']],
                'original legacy account retains login or supplementary privileges')
        require(self.account_status()==('L','1970-01-02'),'original legacy account is not locked and expired')
        require(ssh_sources()==value['ssh'] and protected(SSH_FILE)==SSH_DENIAL,'original SSH retirement fence changed')
        self.ssh_effective(True)
        require(sha(protected('/etc/sudoers'))==value['candidate_sha256'],'original sudo retirement policy changed')
        self.call(['/usr/sbin/visudo','-c'])
        denied=self.call(['/usr/bin/sudo','-n','-l','-U','solv'],success=False)
        require(denied.returncode==1 and re.fullmatch(rb'User solv is not allowed to run sudo on [^\r\n]+\.\n?',denied.stdout+denied.stderr),
                'original legacy account still has sudo authority or policy verification failed')
        self.quiescent(self.scope['uid'])
        return value
    def revoke(self):
        self.authorize(self.scope);self.namespace()
        if (STORE/'original.json').exists():value=self.saved()
        else:
            observed=original_accounts(self.scope)
            self.manager(observed['manager']);self.ssh_effective(False)
            require(not path(SSH_FILE).exists() and not path(SSH_FILE).is_symlink(),'unrecorded SSH denial cannot be adopted')
            raw,candidate,mode=sudo_source();ssh=ssh_sources()
            require(self.account_status()[1]=='never','pre-existing account expiration needs separate qualification')
            original=STORE/'sudoers.original'
            if original.exists():require(read(original,owner=ROOT_UID)==raw,'original sudo backup changed')
            else:atomic(original,raw)
            sync_file(original,ROOT_UID);sync_directory(STORE)
            value={'format':1,'binding':self.scope,'manager':observed['manager'],'ssh':ssh,
                'sudo_sha256':sha(raw),'candidate_sha256':sha(candidate),'sudo_mode':mode,'phase':'reserved'}
            self.put(value)
        value=self.saved();self.manager(value['manager']);original_accounts(self.scope,partial=True)
        raw=read(STORE/'sudoers.original',owner=ROOT_UID)
        require(sha(raw)==value['sudo_sha256'] and raw.count(SUDO_GRANT)==1,'original sudo backup differs')
        candidate=raw.replace(SUDO_GRANT,b'',1);require(sha(candidate)==value['candidate_sha256'],'original sudo candidate differs')
        require(ssh_sources()==value['ssh'],'original SSH configuration changed before retirement')
        denial=path(SSH_FILE)
        if denial.exists() or denial.is_symlink():require(protected(SSH_FILE)==SSH_DENIAL,'SSH denial is not this original retirement')
        else:atomic(denial,SSH_DENIAL,0o644)
        sync_file(denial,ROOT_UID);sync_directory(denial.parent)
        self.ssh_effective(True);self.call(['/usr/bin/systemctl','reload','ssh.service'])
        value['phase']='ssh-denied';self.put(value);self.saved();self.quiescent(self.scope['uid'])
        current=protected('/etc/sudoers')
        require(current in (raw,candidate),'original sudoers changed during retirement')
        if current==raw:
            proposal=STORE/'sudoers.candidate'
            if proposal.exists():require(read(proposal,owner=ROOT_UID)==candidate,'staged sudo candidate changed')
            else:atomic(proposal,candidate,value['sudo_mode'])
            self.call(['/usr/sbin/visudo','-c','-f',str(proposal)])
            atomic(path('/etc/sudoers'),candidate,value['sudo_mode'])
        sync_file(path('/etc/sudoers'),ROOT_UID);sync_directory(path('/etc'))
        account=original_accounts(self.scope,partial=True);locked,expires=self.account_status()
        changes=[]
        if account['shell']!='/usr/sbin/nologin':changes.append(['--shell','/usr/sbin/nologin'])
        if account['groups']!=[self.scope['gid']]:changes.append(['--groups',''])
        if locked!='L':changes.append(['--lock'])
        if expires!='1970-01-02':changes.append(['--expiredate','1'])
        for arguments in changes:
            self.quiescent(self.scope['uid']);self.call(['/usr/sbin/usermod',*arguments,'solv'])
        for name in ('passwd','group','shadow','gshadow'):sync_file(path('/etc/'+name),ROOT_UID)
        sync_directory(path('/etc'))
        self.verify();value['phase']='revoked';self.put(value);self.saved()
        return {'old_login_revoked':True,'original_uid_preserved':True,'original_home_preserved':True,
                'copy_authorized':False,'manager_reauthentication_required':True}

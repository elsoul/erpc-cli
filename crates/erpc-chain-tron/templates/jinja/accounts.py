# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Reserved dedicated runtime identity; never adopt unknown NSS accounts."""
import grp
import os
import pwd
import stat

NAME='tron'
HOME='/var/lib/tron'
SHELL='/usr/sbin/nologin'
RECEIPT='/etc/tron/runtime-account.json'


class Accounts:
    def __init__(self,state,users=pwd.getpwall,groups=grp.getgrall,members=os.getgrouplist):
        self.state,self.users,self.groups,self.members=state,users,groups,members

    def record(self,expected):
        if not self.state.path(RECEIPT).exists():return None
        value=self.state.read(RECEIPT)
        if (set(value)!={'format','contract','uid','gid','state'} or value['format']!=1
                or value['contract']!=expected or value['state'] not in ('reserved','established')
                or any(type(value[key]) is not int or not 100<=value[key]<=999 for key in ('uid','gid'))):
            raise ValueError('runtime account reservation is invalid')
        return value

    def observed(self,record):
        users=list(self.users());groups=list(self.groups())
        named=[user for user in users if user.pw_name==NAME]
        group=[entry for entry in groups if entry.gr_name==NAME]
        if record is None:
            if named or group:raise ValueError('unknown existing runtime account/group cannot be adopted')
            return None,None
        matching=[user for user in users if user.pw_uid==record['uid']]
        matching_groups=[entry for entry in groups if entry.gr_gid==record['gid']]
        if len(named)>1 or len(group)>1:raise ValueError('ambiguous runtime NSS identity')
        if matching!=named or matching_groups!=group:raise ValueError('reserved runtime UID/GID has another owner')
        user=named[0] if named else None;entry=group[0] if group else None
        if entry is not None and (entry.gr_gid!=record['gid'] or set(entry.gr_mem)-{NAME}):
            raise ValueError('runtime primary group changed or grants another account access')
        if any(user.pw_gid==record['gid'] and user.pw_name!=NAME for user in users):
            raise ValueError('another runtime account shares the reserved primary group')
        if user is not None:
            if (entry is None or user.pw_uid!=record['uid'] or user.pw_gid!=record['gid']
                    or user.pw_dir!=HOME or user.pw_shell!=SHELL
                    or set(self.members(NAME,record['gid']))!={record['gid']}):
                raise ValueError('runtime UID/GID/home/shell or supplementary groups changed')
        return user,entry

    def preflight(self,expected):
        record=self.record(expected)
        user,group=self.observed(record)
        if record is not None and record['state']=='established' and (user is None or group is None):
            raise ValueError('original runtime account is missing; implicit replacement refused')
        return record

    def provision(self,expected):
        record=self.preflight(expected)
        if record is None:
            used_users={entry.pw_uid for entry in self.users()};used_groups={entry.gr_gid for entry in self.groups()}
            uid=next((value for value in range(999,99,-1) if value not in used_users),None)
            gid=next((value for value in range(999,99,-1) if value not in used_groups),None)
            if uid is None or gid is None:raise ValueError('no unused system UID/GID available')
            record={'format':1,'contract':expected,'uid':uid,'gid':gid,'state':'reserved'}
            self.state.write(RECEIPT,record)
        user,group=self.observed(record)
        if group is None:self.state.command('/usr/sbin/groupadd','--system','--gid',str(record['gid']),NAME,timeout=60)
        user,group=self.observed(record)
        if user is None:
            self.state.command('/usr/sbin/useradd','--system','--uid',str(record['uid']),'--gid',str(record['gid']),
                '--home-dir',HOME,'--no-create-home','--shell',SHELL,'--groups','',NAME,timeout=60)
        user,group=self.observed(record)
        if user is None or group is None:raise ValueError('runtime account creation did not establish its reserved identity')
        if record['state']!='established':
            record['state']='established';self.state.write(RECEIPT,record,mode=0o644)
        return record

    def verify(self,expected):
        record=self.preflight(expected)
        if record is None or record['state']!='established':
            raise ValueError('original runtime UID/GID receipt missing; reviewed migration required')
        for name in (HOME,'/var/log/tron'):
            path=self.state.path(name)
            if path.exists() or path.is_symlink():
                info=path.lstat()
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=record['uid']
                        or info.st_gid!=record['gid'] or info.st_mode&0o077):
                    raise ValueError('runtime data/log directory differs from its original account')
        return record

    def retained_uid(self):
        path=self.state.path(RECEIPT)
        if not path.exists():return None
        value=self.record(self.state.read('/etc/tron/contract.json'))
        return value['uid']

# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original dedicated account authority for both clients and the private proxy."""
import grp
import json
import os
from pathlib import Path
import pwd

RULES={'bor':('polygon-bor','/var/lib/polygon/bor'),
    'heimdall':('polygon-heimdall','/var/lib/polygon/heimdall'),
    'parent':('polygon-upstreams','/nonexistent')}
VALIDATOR_RULES=dict(RULES,broker=('polygon-rabbitmq','/var/lib/polygon/broker'))
RECEIPT='/etc/polygon/runtime-accounts.json'
RESERVED='/etc/polygon/runtime-accounts.reserved'
SHELL='/usr/sbin/nologin'


def rules(expected):
    return VALIDATOR_RULES if expected is not None and expected.get('role')=='validator' else RULES


def runtime(component,network,parent=False):
    value=json.loads(Path(RECEIPT).read_text())
    if type(value.get('format')) is not int or value.get('format')!=1 or value.get('state')!='established' or component not in rules(value.get('contract')):
        raise ValueError('runtime account authority is missing')
    chain=value['contract']['network']
    wanted=('mainnet' if chain=='mainnet' else 'sepolia') if parent else chain
    record=value['accounts'][component];uid,gid=record['uid'],record['gid']
    if (chain not in ('mainnet','amoy') or network!=wanted
            or type(uid) is not int or type(gid) is not int or not 100<=uid<=999 or not 100<=gid<=999
            or os.getuid()!=uid or os.geteuid()!=uid or os.getgid()!=gid or os.getegid()!=gid
            or set(os.getgroups())-{gid}):
        raise ValueError('actual process privileges differ from the original runtime account')


class Accounts:
    def __init__(self,state,users=pwd.getpwall,groups=grp.getgrall,members=os.getgrouplist):
        self.state,self.users,self.groups,self.members=state,users,groups,members

    def record(self,expected):
        if not self.state.path(RECEIPT).exists():return None
        value=self.state.read(RECEIPT)
        if (set(value)!={'format','contract','accounts','state'} or type(value['format']) is not int or value['format']!=1
                or value['contract']!=expected or value['state'] not in ('reserved','established')
                or set(value['accounts'])!=set(rules(expected))):
            raise ValueError('runtime account reservation is invalid')
        for record in value['accounts'].values():
            if set(record)!={'uid','gid'} or any(type(number) is not int or not 100<=number<=999 for number in record.values()):
                raise ValueError('invalid reserved runtime UID/GID')
        for kind in ('uid','gid'):
            if len({record[kind] for record in value['accounts'].values()})!=len(rules(expected)):
                raise ValueError('runtime components cannot share account authority')
        return value

    @staticmethod
    def lookup(kind,value):
        functions={'user-name':pwd.getpwnam,'user-id':pwd.getpwuid,
            'group-name':grp.getgrnam,'group-id':grp.getgrgid}
        try:return functions[kind](value)
        except KeyError:return None  # Only explicit not-found means absence; other failures propagate.

    def observed(self,value,expected=None):
        users=list(self.users());groups=list(self.groups());found={}
        for component,(name,home) in rules(value['contract'] if value else expected).items():
            named=[entry for entry in users if entry.pw_name==name]
            named_groups=[entry for entry in groups if entry.gr_name==name]
            resolved_user=self.lookup('user-name',name);resolved_group=self.lookup('group-name',name)
            if value is None:
                if named or named_groups or resolved_user is not None or resolved_group is not None:
                    raise ValueError('unknown existing Polygon account/group cannot be adopted')
                continue
            record=value['accounts'][component]
            if (len(named)>1 or len(named_groups)>1
                    or [entry for entry in users if entry.pw_uid==record['uid']]!=named
                    or [entry for entry in groups if entry.gr_gid==record['gid']]!=named_groups):
                raise ValueError('reserved runtime UID/GID has another owner')
            user=named[0] if named else None;group=named_groups[0] if named_groups else None
            if (resolved_user!=user or resolved_group!=group
                    or self.lookup('user-id',record['uid'])!=user or self.lookup('group-id',record['gid'])!=group):
                raise ValueError('keyed NSS lookup differs from the original enumerated runtime account')
            if group is not None and (group.gr_gid!=record['gid'] or set(group.gr_mem)-{name}):
                raise ValueError('runtime primary group changed or shares authority')
            if any(entry.pw_gid==record['gid'] and entry.pw_name!=name for entry in users):
                raise ValueError('another account shares the reserved primary group')
            if user is not None and (group is None or user.pw_uid!=record['uid'] or user.pw_gid!=record['gid']
                    or user.pw_dir!=home or user.pw_shell!=SHELL
                    or set(self.members(name,record['gid']))!={record['gid']}):
                raise ValueError('original UID/GID/home/shell or supplementary groups changed')
            found[component]=(user,group)
        return found

    def preflight(self,expected):
        import host
        value=self.record(expected)
        if value is None:
            prior=(RESERVED,*('/etc/polygon/'+name+'.json' for name in ('installed','identity','history','activation')),
                *('/etc/systemd/system/'+name for name in host.UNITS.values()))
            directories=('/etc/credstore.encrypted/polygon','/var/lib/polygon/bor','/var/lib/polygon/heimdall','/var/lib/polygon/broker')
            if (any(self.state.path(name).exists() or self.state.path(name).is_symlink() for name in prior)
                    or any(self.state.path(name).is_symlink() or self.state.path(name).is_dir() and any(self.state.path(name).iterdir()) for name in directories)):
                raise ValueError('original runtime authority is missing with retained state; reviewed recovery required')
        found=self.observed(value,expected)
        if value is not None and value['state']=='established' and any(None in pair for pair in found.values()):
            raise ValueError('original runtime account is missing; implicit replacement refused')
        return value

    def provision(self,expected):
        import host
        self.state.runtime_owner(expected)
        value=self.preflight(expected)
        if value is None:
            users=list(self.users());groups=list(self.groups())
            used_users={entry.pw_uid for entry in users};used_groups={entry.gr_gid for entry in groups}|{entry.pw_gid for entry in users}
            records={}
            for component in rules(expected):
                uid=next((number for number in range(999,99,-1) if number not in used_users and self.lookup('user-id',number) is None),None)
                gid=next((number for number in range(999,99,-1) if number not in used_groups and self.lookup('group-id',number) is None),None)
                if uid is None or gid is None:raise ValueError('no unused system UID/GID available')
                records[component]={'uid':uid,'gid':gid};used_users.add(uid);used_groups.add(gid)
            value={'format':1,'contract':expected,'accounts':records,'state':'reserved'}
            self.state.write(RECEIPT,value)
        # A separate durable marker prevents silent regeneration if the original
        # account receipt is later lost, including before first native startup.
        host.fence(self.state.protected(RESERVED,missing=True),self.state.root)
        for component,(name,home) in rules(expected).items():
            record=value['accounts'][component];user,group=self.observed(value)[component]
            if group is None:self.state.command('/usr/sbin/groupadd','--system','--gid',str(record['gid']),name,timeout=60)
            user,group=self.observed(value)[component]
            if user is None:
                self.state.command('/usr/sbin/useradd','--system','--uid',str(record['uid']),'--gid',str(record['gid']),
                    '--home-dir',home,'--no-create-home','--shell',SHELL,'--groups','',name,timeout=60)
        if any(None in pair for pair in self.observed(value).values()):raise ValueError('reserved account creation is incomplete')
        if value['state']!='established':
            value['state']='established';self.state.write(RECEIPT,value,mode=0o644)
        return value

    def verify(self,expected):
        self.state.runtime_owner(expected)
        value=self.preflight(expected)
        if value is None or value['state']!='established':raise ValueError('original UID/GID receipt missing; reviewed migration required')
        return value['accounts']

    def retained_uids(self,components=None):
        if components is not None and (not components or not set(components)<=set(VALIDATOR_RULES)):
            raise ValueError('unknown retained runtime account scope')
        if not self.state.path(RECEIPT).exists():return set()
        expected=self.state.read('/etc/polygon/contract.json');expected.pop('runtime_protocol',None)
        selected=set(rules(expected)) if components is None else set(components)
        if not selected<=set(rules(expected)):raise ValueError('retained component does not belong to this role')
        value=self.record(expected)
        return {value['accounts'][name]['uid'] for name in selected}

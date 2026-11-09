# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original Ethereum numeric identities, reserved durably before any NSS mutation."""
import grp
import os
import pwd
from eth_files import require,run,synchronize

PROFILES={
    'rpc':{'shared':'ethereum','users':{'reth':'/var/lib/ethereum/reth','lighthouse':'/var/lib/ethereum/lighthouse'}},
    'validator':{'shared':'ev-engine','users':{'ev-reth':'/nonexistent','ev-beacon':'/nonexistent','ev-validator':'/nonexistent','ev-transport':'/nonexistent'}},
}


def lookup(function,value):
    try:return function(value)
    except KeyError:return None


def snapshot():
    users,groups=pwd.getpwall(),grp.getgrall()
    require(len(users)<=100000 and len(groups)<=100000,'NSS namespace exceeds its bound')
    return users,groups


def profile(role):
    require(role in PROFILES,'unsupported Ethereum account role');return PROFILES[role]


def validate(plan,role):
    selected=profile(role);names=set(selected['users']);group_names={selected['shared']}|(names if role=='validator' else set())
    require(isinstance(plan,dict) and (set(plan)=={'schema','role','users','groups'} or role=='validator' and set(plan)=={'schema','role','users','groups','homes'}) and type(plan['schema'])is int
            and plan['schema']==1 and plan['role']==role and isinstance(plan['users'],dict) and set(plan['users'])==names
            and isinstance(plan['groups'],dict) and set(plan['groups'])==group_names,'invalid original Ethereum identity plan')
    if 'homes' in plan:
        require(isinstance(plan['homes'],dict) and set(plan['homes'])==names
                and all(home=='/nonexistent' or name!='ev-transport' and home=='/home/'+name for name,home in plan['homes'].items()),
                'original migrated service homes differ from the supported historical profile')
    ids=[]
    for name,gid in plan['groups'].items():
        require(type(gid)is int and 100<=gid<=999,'original service group must be a bounded system identity');ids.append(gid)
    require(len(set(ids))==len(ids),'service groups must have distinct original numeric identities')
    ids=[]
    for name,value in plan['users'].items():
        require(isinstance(value,dict) and set(value)=={'uid','gid'} and type(value['uid'])is int
                and 100<=value['uid']<=999 and value['gid']==plan['groups'][selected['shared'] if role=='rpc' else name],
                'original service account does not match its fixed primary group')
        ids.append(value['uid'])
    require(len(ids)==len(set(ids)),'service users must be isolated from each other')
    return plan


def expected_groups(plan,name):
    groups={plan['users'][name]['gid']}
    if plan['role']=='validator' and name in ('ev-reth','ev-beacon'):groups.add(plan['groups']['ev-engine'])
    if plan['role']=='validator' and name=='ev-transport':groups.add(plan['groups']['ev-reth'])
    return groups


def user_fields(value):
    return None if value is None else (value.pw_name,value.pw_uid,value.pw_gid,value.pw_dir,value.pw_shell)


def group_fields(value):
    return None if value is None else (value.gr_name,value.gr_gid,frozenset(value.gr_mem))


def verify(plan,partial=False):
    selected=profile(plan['role']);validate(plan,plan['role']);users,groups=snapshot()
    for name,gid in plan['groups'].items():
        named=lookup(grp.getgrnam,name);numbered=lookup(grp.getgrgid,gid)
        rows=[row for row in groups if row.gr_name==name or row.gr_gid==gid]
        require(len(rows)<=1 and group_fields(named)==group_fields(numbered)
                and group_fields(named)==group_fields(rows[0] if rows else None),
                'original group differs across numeric, named and enumerated NSS')
        require(partial or named is not None,'established original service group is missing')
        if named is not None:
            members={user for user in plan['users'] if gid in expected_groups(plan,user)}
            require(named.gr_gid==gid and set(named.gr_mem)<=members,'original service group was shared with an unknown account')
        for user in users:
            if user.pw_gid==gid:require(user.pw_name in plan['users'],'original service primary group is shared')
    for name,identity in plan['users'].items():
        named=lookup(pwd.getpwnam,name);numbered=lookup(pwd.getpwuid,identity['uid'])
        rows=[row for row in users if row.pw_name==name or row.pw_uid==identity['uid']]
        require(len(rows)<=1 and user_fields(named)==user_fields(numbered)
                and user_fields(named)==user_fields(rows[0] if rows else None),
                'original account differs across numeric, named and enumerated NSS')
        require(partial or named is not None,'established original service account is missing')
        if named is not None:
            actual=set(os.getgrouplist(name,identity['gid']));expected=expected_groups(plan,name)
            require(named.pw_uid==identity['uid'] and named.pw_gid==identity['gid']
                    and named.pw_dir==plan.get('homes',selected['users'])[name] and named.pw_shell=='/usr/sbin/nologin'
                    and (actual<=expected if partial else actual==expected),
                    'original service identity, home, shell or supplementary groups changed')
    return plan


def allocate(role):
    selected=profile(role);users,groups=snapshot();names=set(selected['users']);wanted_groups={selected['shared']}|(names if role=='validator' else set())
    require(not any(row.pw_name in names for row in users) and not any(row.gr_name in wanted_groups for row in groups)
            and all(lookup(pwd.getpwnam,name) is None for name in names)
            and all(lookup(grp.getgrnam,name) is None for name in wanted_groups),'unknown existing Ethereum accounts cannot be adopted')
    used={row.pw_uid for row in users}|{row.pw_gid for row in users}|{row.gr_gid for row in groups}
    available=[number for number in range(999,99,-1) if number not in used
               and lookup(pwd.getpwuid,number) is None and lookup(grp.getgrgid,number) is None]
    require(len(available)>=len(names)+1,'not enough unused original service identities')
    shared=available.pop(0);result={'schema':1,'role':role,'groups':{selected['shared']:shared},'users':{}}
    for name in sorted(names):
        uid=available.pop(0);gid=shared if role=='rpc' else uid
        result['users'][name]={'uid':uid,'gid':gid}
        if role=='validator':result['groups'][name]=gid
    return validate(result,role)


def persist(state,plan,complete=False):
    state.put('accounts-intent.json',plan)
    synchronize(state.directory/'owner.json');synchronize(state.directory/'accounts-intent.json')
    if complete:
        state.put('accounts.json',plan);synchronize(state.directory/'accounts.json')


def provision(state,role):
    if state.exists('accounts.json'):
        plan=validate(state.get('accounts.json'),role)
        require(state.get('accounts-intent.json')==plan,'original identity receipts differ')
        verify(plan);persist(state,plan,True);return plan
    require(not any(state.exists(name) for name in ('layout.json','active.json','engine-jwt.json')),
            'established original account receipt is missing; restore its original backup instead of recreating identity')
    plan=validate(state.get('accounts-intent.json'),role) if state.exists('accounts-intent.json') else allocate(role)
    verify(plan,partial=True);persist(state,plan)
    for name,gid in plan['groups'].items():
        if lookup(grp.getgrnam,name) is None:run(['/usr/sbin/groupadd','--system','--gid',str(gid),name])
    for name,identity in plan['users'].items():
        supplementary=[group for group,gid in plan['groups'].items() if gid in expected_groups(plan,name) and gid!=identity['gid']]
        if lookup(pwd.getpwnam,name) is None:
            args=['/usr/sbin/useradd','--system','--uid',str(identity['uid']),'--gid',str(identity['gid']),
                  '--no-create-home','--home-dir',plan.get('homes',profile(role)['users'])[name],'--shell','/usr/sbin/nologin']
            if supplementary:args.extend(['--groups',','.join(supplementary)])
            run(args+[name])
        elif set(os.getgrouplist(name,identity['gid']))!=expected_groups(plan,name):
            # Only the pending original creation may finish its own membership.
            # Completed identities never enter this path or get repaired.
            verify(plan,partial=True)
            run(['/usr/sbin/usermod','--groups',','.join(supplementary),name])
    verify(plan);persist(state,plan,True);return plan

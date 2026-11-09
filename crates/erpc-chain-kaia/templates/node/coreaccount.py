#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original numeric identity for newly reserved core-cell custody, before NSS mutation."""
import grp
import os
import pwd
NAME='erpc-kaia'


def lookup(function,value):
    try:return function(value)
    except KeyError:return None


def snapshot(c):
    users,groups=pwd.getpwall(),grp.getgrall()
    c.require(len(users)<=100000 and len(groups)<=100000,'account namespace exceeds its bound')
    return users,groups


def reserve(c):
    users,groups=snapshot(c)
    c.require(lookup(pwd.getpwnam,NAME) is None and lookup(grp.getgrnam,NAME) is None and
              not any(item.pw_name==NAME for item in users) and not any(item.gr_name==NAME for item in groups),
              'unowned core-cell account cannot be adopted')
    used={item.pw_uid for item in users}|{item.pw_gid for item in users}|{item.gr_gid for item in groups}
    for number in range(999,99,-1):
        if number not in used and lookup(pwd.getpwuid,number) is None and lookup(grp.getgrgid,number) is None:
            return {'service_uid':number,'service_gid':number}
    raise c.Refused('an unused dedicated core-cell system identity is required')


def verify(c,state,missing=False):
    uid,gid=state.get('service_uid'),state.get('service_gid')
    c.require(type(uid)is int and type(gid)is int and uid==gid and 100<=uid<=999,'original core-cell numeric reservation is unavailable')
    users,groups=snapshot(c)
    named=[item for item in users if item.pw_name==NAME];named_groups=[item for item in groups if item.gr_name==NAME]
    def user(value):return None if value is None else (value.pw_name,value.pw_uid,value.pw_gid,value.pw_dir,value.pw_shell)
    def group(value):return None if value is None else (value.gr_name,value.gr_gid,frozenset(value.gr_mem))
    byname=lookup(pwd.getpwnam,NAME);bygroup=lookup(grp.getgrnam,NAME)
    c.require(len(named)<=1 and len(named_groups)<=1 and user(byname)==user(named[0] if named else None) and
              user(byname)==user(lookup(pwd.getpwuid,uid)) and group(bygroup)==group(named_groups[0] if named_groups else None) and
              group(bygroup)==group(lookup(grp.getgrgid,gid)) and
              not any((item.pw_uid==uid or item.pw_gid==gid) and item.pw_name!=NAME for item in users) and
              not any(item.gr_gid==gid and item.gr_name!=NAME for item in groups),'original core-cell identity differs across NSS authority')
    if bygroup is not None:
        c.require(bygroup.gr_gid==gid and not set(bygroup.gr_mem)-{NAME},'original core-cell group is shared or changed')
    if byname is not None:
        c.require(bygroup is not None and byname.pw_uid==uid and byname.pw_gid==gid and byname.pw_dir=='/nonexistent' and
                  byname.pw_shell=='/usr/sbin/nologin' and set(os.getgrouplist(NAME,gid))=={gid},'core-cell identity profile or supplementary groups changed')
    c.require(missing or (byname is not None and bygroup is not None),'original core-cell account is missing')
    return byname,bygroup


def provision(c,state):
    c.require(state['role']=='validator','core-cell account provisioning requires its original role')
    established=state.get('account_established') is True
    user,group=verify(c,state,missing=not established)
    # A visible but not yet durably published receipt cannot authorize NSS writes.
    # Every retry synchronizes it again before a group/user can be created.
    c.save(state)
    for path in (c.ROOT,*c.ROOT.parents):
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        if path==c.TRUST_ANCHOR:break
    if group is None:
        c.run(['/usr/sbin/groupadd','--system','--gid',str(state['service_gid']),NAME])
    user,_=verify(c,state,missing=True)
    if user is None:
        c.run(['/usr/sbin/useradd','--system','--uid',str(state['service_uid']),'--gid',str(state['service_gid']),
               '--no-create-home','--home-dir','/nonexistent','--shell','/usr/sbin/nologin',NAME])
    verify(c,state)
    if not established:
        state['account_established']=True;c.save(state)
    return {'original_account':'verified'}

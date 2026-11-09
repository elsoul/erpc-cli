# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Refuse other active/queued managed operations without signaling unknown PIDs."""
import re

def require(condition,message):
    if not condition:raise ValueError(message)

def other_runs_idle(run,current=None):
    jobs=run(['/usr/bin/systemctl','list-jobs','--no-legend','--no-pager'])
    for line in jobs.splitlines():
        fields=line.split()
        if not fields:continue
        require(len(fields)>=4 and fields[0].isdigit(),'ambiguous managed job metadata')
        if re.fullmatch(r'erpc-r-[a-z0-9-]+\.service',fields[1]):
            require(fields[1]==current,'another managed operation is queued; retain the original node')
    raw=run(['/usr/bin/systemctl','list-units','--all','--type=service','--plain','--no-legend','--no-pager'])
    for line in raw.splitlines():
        fields=line.split();require(len(fields)>=4,'ambiguous managed service metadata')
        name=fields[0]
        if re.fullmatch(r'erpc-r-[a-z0-9-]+\.service',name) is None or name==current:continue
        observed={}
        for row in run(['/usr/bin/systemctl','show',name,'--property=LoadState,ActiveState,SubState,MainPID,ControlPID,Restart']).splitlines():
            key,separator,value=row.partition('=');require(separator and key not in observed,'ambiguous managed operation state');observed[key]=value
        require(observed.get('LoadState') in ('loaded','not-found') and observed.get('ActiveState') in ('inactive','failed')
                and observed.get('SubState') in ('dead','failed') and observed.get('MainPID')=='0' and observed.get('ControlPID')=='0'
                and observed.get('Restart')=='no','another managed operation can still change the original source')


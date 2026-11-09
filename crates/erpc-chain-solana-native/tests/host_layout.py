#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual host/account/directory composition; metadata and NSS effects are inert."""
import importlib.util,json,os,stat,sys
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'tests'));sys.path.insert(0,str(root/'templates/node'))
import native_host as host,native_files as files,native_accounts as accounts,native_state as lifecycle
import native_source_floor as floor
from mounts import owner
spec=importlib.util.spec_from_file_location('review_accounts',root/'tests/accounts.py');tests=importlib.util.module_from_spec(spec);spec.loader.exec_module(tests)
t=tests.AccountReservation();t.setUp()
try:
 home=Path(accounts.SPECS['node'][1]);state=home/'state';t.state_path=state;t.state=lifecycle.State(state);t.contract=owner()
 volumes={name:t.root/('volume-'+name) for name in ('accounts','ledger','snapshots')}
 for path in volumes.values():path.mkdir()
 real_stat=Path.lstat;owners={};real_ensure=accounts.ensure
 def metadata(path,*a,**kw):
  value=real_stat(path,*a,**kw);values=list(value)
  if path==t.root or t.root in path.parents:
   values[4],values[5]=owners.get(path,(0,0))
  else:values[0]=stat.S_IFDIR|0o755;values[4]=0;values[5]=0
  return os.stat_result(values)
 with patch.object(Path,'lstat',metadata),patch.object(os,'chown',side_effect=lambda path,uid,gid:owners.__setitem__(path,(uid,gid))),\
  patch.object(host,'HOME',home),patch.object(host,'STATE',state),patch.object(host,'MOUNTS',volumes),patch.object(host,'CONFIG_ROOT',t.root/'config'),\
  patch.object(floor.units,'MOUNTS',volumes),patch.object(floor,'sync_file',side_effect=lambda path:files.sync_file(path,os.getuid())),\
  patch.object(host,'root_directory',files.root_directory),patch.object(accounts,'root_directory',files.root_directory),\
  patch.object(host,'sync_file',side_effect=lambda path:files.sync_file(path,os.getuid())),\
  patch.object(host,'platform_facts',return_value={}),patch.object(host.mounts,'inspect',return_value={}),\
  patch.object(host.process,'assert_quiescent'),patch.object(host.tuning,'configure',return_value={}),\
  patch.object(accounts,'ensure',side_effect=lambda state,contract:real_ensure(state,contract,t.account_command)):
  result=host.prepare(t.contract,lambda *a,**k:'not-found\n')
  mode=stat.S_IMODE(home.lstat().st_mode);identity=result['accounts']['node']
  assert mode == 0o755 and stat.S_IMODE(state.lstat().st_mode) == 0o700
  assert result['prepared'] and identity['uid'] != 0
  print(json.dumps({'prepared':result['prepared'],'home_mode':oct(mode),'home_owner':home.lstat().st_uid,'original_runtime_uid':identity['uid'],'original_runtime_gid':identity['gid'],'node_may_search_home':bool(mode&1),'state_mode':oct(stat.S_IMODE(state.lstat().st_mode)),'NSS_commands_inert':len(t.calls),'real_uid_or_privileged_paths_changed':False},indent=2))
finally:t.tearDown()

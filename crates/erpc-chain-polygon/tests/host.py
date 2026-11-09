# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual controller paths with Linux proc-shaped files and a live inert writer."""
import importlib.util
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))


def module(name):
    spec=importlib.util.spec_from_file_location('polygon_fixture_'+name,ROOT/'tests'/(name+'.py'))
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result


@unittest.skipUnless(os.name=='posix','host process authority uses POSIX filesystem semantics')
class Authority(unittest.TestCase):
    def setUp(self):
        import host
        self.host=host;self.fixture=module('control').Lifecycle();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.fixture.activate();self.fixture.running.clear();self.root=self.fixture.root;self.state=self.fixture.state
        self.proof=host.Proof(self.state,lookup=lambda name:SimpleNamespace(pw_uid={'polygon-bor':1001,'polygon-heimdall':1002,'polygon-upstreams':1003}[name]))
        self.state.proof=self.proof;self.pids={};self.ports=[]
        (self.root/'proc/net').mkdir(parents=True)
        for family in ('tcp','tcp6','udp','udp6'):(self.root/'proc/net'/family).write_text('header\n')
        for name in host.UNITS:
            directory=self.root/'sys/fs/cgroup/system.slice'/host.UNITS[name];directory.mkdir(parents=True);(directory/'cgroup.procs').write_text('')
        self.process(1,0,'/sbin/init',[b'/sbin/init'],'/init.scope')
        original=self.state.run
        def run(args,**kwargs):
            if args[:2]==['systemctl','show']:
                component=next((name for name,unit in host.UNITS.items() if unit==args[-1]),None)
                if component and '--property=ControlGroup' in args:
                    out=('/system.slice/'+host.UNITS[component]) if component in self.pids else ''
                    return subprocess.CompletedProcess(args,0,out.encode(),b'')
                if component and '--property=MainPID' in args:
                    return subprocess.CompletedProcess(args,0,str(self.pids.get(component,0)).encode(),b'')
            return original(args,**kwargs)
        self.state.run=run
        self.installed=self.state.read('/etc/polygon/installed.json')
    def process(self,pid,uid,executable,args,group,generation='101',descriptors=()):
        path=self.root/'proc'/str(pid);path.mkdir(exist_ok=True)
        (path/'fd').mkdir(exist_ok=True)
        (path/'stat').write_text(str(pid)+' (inert fixture) S '+'0 '*18+generation+' 0\n')
        (path/'status').write_text('State:\tS (sleeping)\nUid:\t'+(' '.join([str(uid)]*4))+'\nGid:\t'+' '.join([str(uid)]*4)+'\nGroups:\t'+str(uid)+'\n')
        (path/'cmdline').write_bytes(b'\0'.join(args)+b'\0')
        (path/'cgroup').write_text('0::'+group+'\n')
        if (path/'exe').is_symlink():(path/'exe').unlink()
        (path/'exe').symlink_to(executable)
        for index,target in enumerate(descriptors):(path/'fd'/str(index)).symlink_to(target)
        return path
    def native(self,component,pid):
        uid=self.proof.uid(component);group='/system.slice/'+self.host.UNITS[component]
        if component=='parent':
            exe=os.path.realpath('/usr/bin/python3');args=['/usr/bin/python3','-I','/usr/local/lib/erpc/polygon/releases/'+self.installed['helpers']+'/parent.py','sepolia']
        else:
            exe=self.installed['binaries'][component]['directory']+'/usr/bin/'+('bor' if component=='bor' else 'heimdalld')
            args=[exe,'server','-config','/etc/polygon/bor.toml'] if component=='bor' else [exe,'start','--home','/var/lib/polygon/heimdall','--chain','amoy','--rest-server','--bridge=false']
        sockets=[]
        for index,port in enumerate(self.host.PORTS[component]):
            inode=str(pid*10+index);sockets.append('socket:['+inode+']')
            self.ports.append((port,uid,inode))
        kernel_exe=exe if component=='parent' else str(self.state.path(exe))
        self.process(pid,uid,kernel_exe,[arg.encode() for arg in args],group,descriptors=sockets)
        (self.root/'sys/fs/cgroup'/group.lstrip('/')/'cgroup.procs').write_text(str(pid)+'\n')
        self.pids[component]=pid;self.fixture.running.add(self.host.UNITS[component]);self.tables()
    def tables(self):
        rows=['0: 0100007F:'+format(port,'04X')+' 00000000:0000 0A 0:0 00:0 0 '+str(uid)+' 0 '+inode for port,uid,inode in self.ports]
        (self.root/'proc/net/tcp').write_text('header\n'+'\n'.join(rows)+'\n' if rows else 'header\n')
    def healthy_queries(self):
        observer=module('observe').Observer();observer.setUp();observer.profile=self.fixture.profile
        self.fixture.control.query=observer.query
        self.fixture.control.sleep=lambda _:setattr(observer,'height',observer.height+3)
        self.fixture.control.ws=lambda _:True
        return observer
    def original_accounts(self):
        import accounts
        records={name:{'uid':uid,'gid':uid} for name,uid in [('bor',999),('heimdall',998),('parent',997)]}
        users=[SimpleNamespace(pw_name=accounts.RULES[name][0],pw_uid=value['uid'],pw_gid=value['gid'],
            pw_dir=accounts.RULES[name][1],pw_shell=accounts.SHELL) for name,value in records.items()]
        groups=[SimpleNamespace(gr_name=user.pw_name,gr_gid=user.pw_gid,gr_mem=[]) for user in users]
        self.state.write(accounts.RECEIPT,{'format':1,'state':'established','contract':self.fixture.contract,'accounts':records})
        authority=accounts.Accounts(self.state,lambda:users,lambda:groups,lambda name,gid:[gid])
        def lookup(kind,value):
            entries,field={'user-name':(users,'pw_name'),'user-id':(users,'pw_uid'),
                'group-name':(groups,'gr_name'),'group-id':(groups,'gr_gid')}[kind]
            return next((entry for entry in entries if getattr(entry,field)==value),None)
        authority.lookup=lookup
        self.state.accounts=authority
        self.proof.lookup=lambda name:next(user for user in users if user.pw_name==name)
        self.assertEqual(authority.verify(self.fixture.contract),records)
        return authority

    def test_real_original_account_receipts_allow_owned_prerequisites_but_refuse_target_orphans(self):
        original=self.original_accounts()
        self.assertEqual(original.retained_uids(),{997,998,999})
        self.native('parent',300);self.healthy_queries()
        self.proof.listener('parent',self.installed)
        self.fixture.control.runtime(self.fixture.contract,'heimdall')
        self.native('heimdall',200)
        self.proof.listener('heimdall',self.installed)
        self.fixture.control.runtime(self.fixture.contract,'bor')
        # A component-local guard still rejects that component's original UID,
        # even while both of its legitimate prerequisite services are running.
        path=self.process(400,999,'/usr/bin/inert',[b'inert'],'/untracked.scope')
        with self.assertRaises(ValueError):self.fixture.control.runtime(self.fixture.contract,'bor')
        lookup=self.proof.lookup
        self.proof.lookup=lambda name:SimpleNamespace(pw_uid=2001) if name=='polygon-bor' else lookup(name)
        with self.assertRaises(ValueError):self.proof.startable('bor')
        self.proof.lookup=lookup
        shutil.rmtree(path)
        self.fixture.control.runtime(self.fixture.contract,'bor')

    def test_global_drain_retains_every_original_uid_after_current_nss_drift(self):
        self.original_accounts()
        self.proof.lookup=lambda name:SimpleNamespace(pw_uid={'polygon-bor':2001,'polygon-heimdall':2002,'polygon-upstreams':2003}[name])
        for uid in (997,998,999):
            path=self.process(400,uid,'/usr/bin/inert',[b'inert'],'/untracked.scope')
            for action in ('stop','destroy'):
                with self.assertRaises(ValueError):self.fixture.control.dispatch(dict(self.fixture.request,action=action))
                self.assertTrue(self.fixture.policy)
            shutil.rmtree(path)
        self.state.stopped()

    def test_dedicated_runtime_names_cannot_alias_the_same_uid(self):
        self.proof.lookup=lambda name:SimpleNamespace(pw_uid=1001)
        with self.assertRaises(ValueError):self.state.stopped()
        with self.assertRaises(ValueError):self.proof.startable('parent')

    def test_original_uid_remains_part_of_drain_when_nss_changes(self):
        self.process(400,1001,'/usr/bin/sleep',[b'sleep',b'60'],'/untracked.scope')
        self.proof.lookup=lambda name:SimpleNamespace(pw_uid={'polygon-bor':2001,'polygon-heimdall':2002,'polygon-upstreams':2003}[name])
        with patch.object(self.state.accounts,'retained_uids',return_value={1001,1002,1003}):
            with self.assertRaises(ValueError):self.state.stopped()

    def test_native_gid_and_supplementary_authority_must_match_original_account(self):
        self.native('bor',201);self.proof.listener('bor',self.installed)
        status=self.root/'proc/201/status';original=status.read_text()
        for altered in (original.replace('Groups:\t1001','Groups:\t1001 9988'),original.replace('Gid:\t1001 1001 1001 1001','Gid:\t9988 9988 9988 9988')):
            status.write_text(altered)
            with self.assertRaises(ValueError):self.proof.listener('bor',self.installed)
        status.write_text(original)

    def test_first_init_refuses_foreign_native_process_before_creating_ownership(self):
        import control,state
        self.process(456,999,'/other/bor',[b'bor'],'/other.scope')
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'etc').mkdir()
            shutil.copyfile(self.root/'etc/os-release',root/'etc/os-release')
            shutil.copytree(self.root/'proc',root/'proc',symlinks=True)
            shutil.copytree(self.root/'sys',root/'sys',symlinks=True)
            fresh=state.State(root,self.state.run,owner=os.getuid())
            command=fresh.command
            def observed(*args,**kwargs):
                if args[0]=='/usr/bin/systemd-detect-virt':return subprocess.CompletedProcess(args,1,b'none\n',b'')
                return command(*args,**kwargs)
            fresh.command=observed
            self.assertEqual(fresh.resources(self.fixture.contract)['effective_logical_cpus'],16)
            fresh.proof=self.host.Proof(fresh,lookup=self.proof.lookup)
            instance=control.Control(fresh,self.fixture.source)
            with self.assertRaisesRegex(ValueError,'unmanaged Polygon'):instance.reserve(self.fixture.contract)
            self.assertFalse((root/'etc/polygon').exists())

    def test_actual_writer_survives_unit_mocks_but_blocks_mutation_and_firewall_removal(self):
        data=self.root/'var/lib/polygon/bor/data';data.mkdir(parents=True,exist_ok=True)
        writer=subprocess.Popen([sys.executable,'-I','-c','import sys,time; from pathlib import Path; p=Path(sys.argv[2])/"inert-writer"; [(p.write_text(str(i)),time.sleep(.02)) for i in range(3000)]','--datadir',str(data)])
        self.addCleanup(lambda: writer.poll() is None and (writer.terminate(),writer.wait(timeout=3)))
        def next_write(after):
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                self.assertIsNone(writer.poll())
                try:
                    counter = (data / 'inert-writer').read_text()
                except FileNotFoundError:
                    counter = ''
                if counter.isdecimal() and int(counter) > after:
                    return int(counter)
                time.sleep(.01)
            self.fail(f'orphan writer did not advance past {after}')
        next_write(-1)
        self.process(writer.pid,1001,sys.executable,[sys.executable.encode(),b'--datadir',str(data).encode()],'/untracked.scope')
        original=self.state.read('/etc/polygon/identity.json')
        for action in ('start','restart','prepare','destroy'):
            with self.assertRaises(ValueError):self.fixture.control.dispatch(dict(self.fixture.request,action=action))
            self.assertTrue(self.fixture.policy);self.assertEqual(self.state.read('/etc/polygon/identity.json'),original)
            self.assertIsNone(writer.poll())
        before = next_write(-1)
        next_write(before)
    def test_foreign_executable_shared_data_and_unreadable_or_reused_pid_fail_closed(self):
        data=self.root/'var/lib/polygon/bor/data';data.mkdir(parents=True,exist_ok=True);(data/'fixture').write_text('retained')
        path=self.process(456,999,'/usr/bin/unrelated',[b'unrelated'],'/other.scope',descriptors=[str(data/'fixture')])
        with self.assertRaises(ValueError):self.state.stopped()
        (path/'fd/0').unlink()
        with patch.object(self.proof,'process',side_effect=PermissionError('inert inaccessible process')):
            with self.assertRaises(PermissionError):self.fixture.control.dispatch(dict(self.fixture.request,action='destroy'))
        self.assertTrue(self.fixture.policy)
        original=self.proof.generation;calls={}
        def reused(pid):
            calls[pid]=calls.get(pid,0)+1
            return '202' if pid==456 and calls[pid]>1 else original(pid)
        with patch.object(self.proof,'generation',side_effect=reused):
            with self.assertRaises(ValueError):self.state.stopped()
    def test_foreign_uid_broker_data_writer_blocks_global_drain_without_killing_it(self):
        data=self.state.path('/var/lib/polygon/broker');data.mkdir()
        self.process(456,12345,'/usr/bin/inert',[b'inert','--datadir'.encode(),str(data).encode()],'/foreign.scope')
        with self.assertRaisesRegex(ValueError,'unmanaged Polygon'):self.state.stopped()
        with self.assertRaises(ValueError):self.fixture.control.stop(self.fixture.contract,retire=True)
        self.assertTrue(self.fixture.policy)
        self.assertTrue(self.state.path('/proc/456').exists())

    def test_cgroup_or_dedicated_uid_cannot_hide_behind_missing_units(self):
        self.process(456,1002,'/usr/bin/inert',[b'inert'],'/other.scope')
        with self.assertRaises(ValueError):self.state.stopped()
        (self.root/'proc/456/status').write_text('State:\tZ (zombie)\nUid:\t1002 1002 1002 1002\n')
        self.state.stopped()
        (self.root/'sys/fs/cgroup/system.slice/polygon-heimdall.service/cgroup.procs').write_text('789\n')
        with self.assertRaises(ValueError):self.state.stopped()
    def test_unknown_tcp_or_udp_listener_prevents_firewall_teardown(self):
        for family,port in [('tcp',9545),('udp',30303)]:
            file=self.root/'proc/net'/family
            file.write_text('header\n0: 00000000:'+format(port,'04X')+' 00000000:0000 '+('0A' if family=='tcp' else '07')+' 0:0 00:0 0 999 0 4567\n')
            with self.assertRaises(ValueError):self.fixture.control.dispatch(dict(self.fixture.request,action='destroy'))
            self.assertTrue(self.fixture.policy)
            file.write_text('header\n')

    def test_fresh_forged_replies_do_not_supply_inactive_service_authority(self):
        self.healthy_queries()
        self.assertFalse(self.fixture.control.status(self.fixture.contract)['ready'])
        for component in ('heimdall','bor'):
            with self.assertRaises(ValueError):self.fixture.control.runtime(self.fixture.contract,component)
    def test_all_listener_owners_match_and_replacement_or_foreign_inode_is_rejected(self):
        for component,pid in [('parent',300),('heimdall',200),('bor',100)]:self.native(component,pid)
        self.healthy_queries();self.assertTrue(self.fixture.control.status(self.fixture.contract)['ready'])
        self.ports=[(port,uid,'99999' if port==9545 else inode) for port,uid,inode in self.ports];self.tables()
        self.assertFalse(self.fixture.control.status(self.fixture.contract)['ready'])
        self.ports=[(port,uid,'3000' if port==9545 else inode) for port,uid,inode in self.ports];self.tables()
        original=self.fixture.control.query
        def replace(port,path='/',payload=None):
            result=original(port,path,payload)
            if port==1317:(self.root/'proc/200/stat').write_text('200 (replacement) S '+'0 '*18+'999 0\n')
            return result
        self.fixture.control.query=replace
        self.assertFalse(self.fixture.control.status(self.fixture.contract)['ready'])
    def test_ipv6_query_listener_and_private_loopback_bindings_have_owned_inodes(self):
        self.native('bor',100)
        (self.root/'proc/net/tcp').write_text('header\n')
        rows=['0: '+'0'*32+':'+format(port,'04X')+' '+'0'*32+':0000 0A 0:0 00:0 0 '+str(uid)+' 0 '+inode for port,uid,inode in self.ports]
        (self.root/'proc/net/tcp6').write_text('header\n'+'\n'.join(rows)+'\n')
        self.proof.listener('bor',self.installed)
        self.native('heimdall',200)
        contents=(self.root/'proc/net/tcp').read_text().replace('0100007F:'+format(26657,'04X'),'00000000:'+format(26657,'04X'))
        (self.root/'proc/net/tcp').write_text(contents)
        with self.assertRaises(ValueError):self.proof.listener('heimdall',self.installed)

    def test_deleted_or_replaced_native_executable_is_not_a_listener_authority(self):
        self.native('heimdall',200)
        link=self.root/'proc/200/exe';original=os.readlink(link)
        link.unlink();link.symlink_to(original+' (deleted)')
        with self.assertRaises(ValueError):self.proof.listener('heimdall',self.installed)
        link.unlink();link.symlink_to(original)
        stat=Path.stat
        def replaced(path,*args,**kwargs):
            result=stat(path,*args,**kwargs)
            if path==link:return SimpleNamespace(st_dev=result.st_dev,st_ino=result.st_ino+1)
            return result
        with patch.object(Path,'stat',replaced):
            with self.assertRaises(ValueError):self.proof.listener('heimdall',self.installed)

    def test_owned_heimdall_progress_is_visible_before_bor_has_a_listener(self):
        self.native('parent',300);self.native('heimdall',200);self.healthy_queries()
        value=self.fixture.control.status(self.fixture.contract)
        self.assertFalse(value['ready']);self.assertTrue(value['heimdall']['available'])
        self.assertTrue(value['heimdall']['advancing']);self.assertFalse(value['bor']['available'])
        self.assertEqual(value['service_ownership'],{'parent':True,'heimdall':True,'bor':False})

    def test_valid_prerequisite_with_no_self_writer_allows_retry_but_spoofing_does_not(self):
        self.native('parent',300);self.healthy_queries()
        self.fixture.control.runtime(self.fixture.contract,'heimdall')
        self.native('heimdall',200)
        self.fixture.control.runtime(self.fixture.contract,'bor')
        self.ports=[(port,999 if port==1317 else uid,inode) for port,uid,inode in self.ports];self.tables()
        with self.assertRaises(ValueError):self.fixture.control.runtime(self.fixture.contract,'bor')


@unittest.skipUnless(os.name=='posix','directory fsync is a managed Linux requirement')
class Durability(unittest.TestCase):
    def setUp(self):
        import host
        self.host=host;self.fixture=module('control').Lifecycle();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.fixture.activate()
    def test_stop_fence_and_intent_are_durable_before_draining_or_teardown(self):
        events=[];original_sync=self.host.sync_directory;original_run=self.fixture.state.run
        def sync(path):events.append(('directory',str(path)));return original_sync(path)
        def run(args,**kwargs):events.append(('command',args));return original_run(args,**kwargs)
        self.fixture.state.run=run
        with patch.object(self.host,'sync_directory',side_effect=sync):self.fixture.control.dispatch(dict(self.fixture.request,action='destroy'))
        stop=next(index for index,event in enumerate(events) if event[0]=='command' and event[1][:3]==['systemctl','disable','--now'])
        self.assertTrue(any(kind=='directory' and path==str(self.fixture.root/'etc/polygon') for kind,path in events[:stop]))
        self.assertFalse(self.fixture.policy)
    def test_sync_failure_still_disables_and_drains_but_retains_filter(self):
        before=len(self.fixture.calls)
        with patch.object(self.host,'sync_directory',side_effect=OSError('inert durability failure')):
            with self.assertRaises(OSError):self.fixture.control.dispatch(dict(self.fixture.request,action='destroy'))
        self.assertTrue(any(args[:3]==['systemctl','disable','--now'] for args in self.fixture.calls[before:]))
        self.assertFalse(self.fixture.running);self.assertTrue(self.fixture.policy)
        self.assertTrue(self.fixture.state.path('/etc/polygon/stopped').exists())
        with self.assertRaises(ValueError):self.fixture.control.runtime(self.fixture.contract,'parent')
    def test_cancellation_and_activation_sync_failures_never_start_services(self):
        self.fixture.control.stop(self.fixture.contract)
        before=len(self.fixture.calls)
        with patch.object(self.host,'sync_directory',side_effect=OSError('inert cancellation failure')):
            with self.assertRaises(OSError):self.fixture.control.start(self.fixture.contract)
        self.assertFalse(self.fixture.running);self.assertTrue(self.fixture.state.path('/etc/polygon/stopped').exists())
        self.assertFalse(any(args[:2]==['systemctl','start'] for args in self.fixture.calls[before:]))
        self.fixture.state.prepare(self.fixture.contract,self.fixture.request['intent'],self.fixture.profile,self.fixture.control.helpers)
        before=len(self.fixture.calls)
        with patch.object(self.host,'sync_directory',side_effect=OSError('inert activation failure')):
            with self.assertRaises(OSError):self.fixture.control.activate(dict(self.fixture.request,firewall={'run':self.fixture.confirmed[0],'bundle':self.fixture.confirmed[1]}))
        self.assertTrue(self.fixture.state.path('/etc/polygon/preparing').exists())
        self.assertFalse(any(args[:2]==['systemctl','start'] for args in self.fixture.calls[before:]))
        with self.assertRaises(ValueError):self.fixture.control.runtime(self.fixture.contract,'parent')

    def test_recovery_sync_failure_retains_fence_and_never_resets_history(self):
        backup=self.fixture.control.backup(self.fixture.contract)
        self.fixture.control.stop(self.fixture.contract)
        history=self.fixture.state.path('/var/lib/polygon/heimdall/data/priv_validator_state.json');before=history.read_bytes()
        self.fixture.state.path('/etc/credstore.encrypted/polygon/original/bor-nodekey').unlink()
        with patch.object(self.host,'sync_directory',side_effect=OSError('inert recovery failure')):
            with self.assertRaises(OSError):self.fixture.control.restore(self.fixture.contract,backup)
        self.assertEqual(history.read_bytes(),before);self.assertFalse(self.fixture.running)
        self.assertTrue(self.fixture.state.path('/etc/polygon/stopped').exists())
        self.fixture.control.restore(self.fixture.contract,backup)
        self.assertEqual(history.read_bytes(),before)




@unittest.skipUnless(os.name=='posix','validator listeners use inert proc/NSS and real account receipts')
class ValidatorAuthority(unittest.TestCase):
    def setUp(self):
        self.fixture=Authority();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        fixture=self.fixture;self.state=fixture.state;self.proof=fixture.proof
        authority=fixture.original_accounts()
        expected=dict(fixture.fixture.contract,role='validator',signer='0x'+'1'*40,stake_owner='0x'+'2'*40)
        self.state.write('/etc/polygon/contract.json',dict(expected,runtime_protocol=3))
        storage=self.state.read('/etc/polygon/storage.json');storage['contract']=expected
        self.state.write('/etc/polygon/storage.json',storage)
        record=self.state.read('/etc/polygon/runtime-accounts.json');record['contract']=expected
        record['accounts']['broker']={'uid':996,'gid':996}
        authority.users().append(SimpleNamespace(pw_name='polygon-rabbitmq',pw_uid=996,pw_gid=996,
            pw_dir='/var/lib/polygon/broker',pw_shell='/usr/sbin/nologin'))
        authority.groups().append(SimpleNamespace(gr_name='polygon-rabbitmq',gr_gid=996,gr_mem=[]))
        self.state.write('/etc/polygon/runtime-accounts.json',record)
        self.installed=dict(fixture.installed,contract=expected,profile=dict(fixture.installed['profile'],validator={'phase':'observing'}))
        self.rows=[]
    def table(self):
        import ipaddress
        rows=[]
        for address,port,uid,inode in self.rows:
            encoded=ipaddress.ip_address(address).packed[::-1].hex()
            rows.append('0: '+encoded+':'+format(port,'04X')+' 00000000:0000 0A 0:0 00:0 0 '+str(uid)+' 0 '+inode)
        self.state.path('/proc/net/tcp').write_text('header\n'+'\n'.join(rows)+'\n')
    def native(self,component,pid):
        fixture=self.fixture;fixture.native(component,pid)
        uid=self.proof.uid(component);path=self.state.path('/proc/'+str(pid))
        if component=='parent':
            for index,(address,port) in enumerate((('127.0.0.10',9545),('127.0.0.11',8545),('127.0.0.12',1317))):
                inode=str(pid*10+index);fd=path/'fd'/str(index)
                if fd.is_symlink():fd.unlink()
                fd.symlink_to('socket:['+inode+']');self.rows.append((address,port,uid,inode))
        else:
            socket_path='/run/polygon-'+component+('/native.rpc' if component=='bor' else '/native.rest')
            inode=str(pid*10+(2 if component=='heimdall' else 0));directory=path/'net';directory.mkdir()
            if component=='heimdall':(path/'fd/2').symlink_to('socket:['+inode+']')
            (directory/'unix').write_text('Num RefCount Protocol Flags Type St Inode Path\n0: 00000002 00000000 00010000 0001 01 '+inode+' '+socket_path+'\n')
            if component=='heimdall':
                executable=self.installed['binaries']['heimdall']['directory']+'/usr/bin/heimdalld'
                args=[executable,'start','--home','/var/lib/polygon/heimdall','--chain','amoy','--rest-server','--bridge=false',
                    '--app','/run/credentials/polygon-heimdall.service/native-app.toml']
                (path/'cmdline').write_bytes(b'\0'.join(arg.encode() for arg in args)+b'\0')
                self.rows.append(('127.0.0.13',26657,uid,str(pid*10)))
        self.table()
    def test_original_accounts_and_running_adapter_do_not_block_native_prerequisite_start(self):
        self.assertEqual(self.state.accounts.retained_uids(),{996,997,998,999})
        self.native('parent',300);self.proof.listener('parent',self.installed)
        self.proof.startable('heimdall',self.installed)
        self.native('heimdall',200);self.proof.listener('heimdall',self.installed)
        self.proof.startable('bor',self.installed)
        self.native('bor',100);self.proof.listener('bor',self.installed)
        with self.assertRaises(ValueError):self.proof.quiescent()
    def test_native_listener_rebinding_and_missing_unix_peer_never_establish_readiness(self):
        self.native('parent',300);self.native('heimdall',200);self.native('bor',100)
        before=list(self.rows);self.rows[0]=('127.0.0.1',*self.rows[0][1:]);self.table()
        with self.assertRaises(ValueError):self.proof.listener('parent',self.installed)
        self.rows=before;self.table();self.proof.listener('parent',self.installed)
        self.state.path('/proc/100/net/unix').write_text('header\n')
        with self.assertRaises(ValueError):self.proof.listener('bor',self.installed)
    def test_first_credential_condition_refuses_an_orphan_original_observer_uid(self):
        controller=self.fixture.fixture.control;expected=self.installed['contract']
        self.fixture.fixture.unit_recipients['polygon-heimdall.service']=(998,998)
        with patch.object(controller,'runtime',return_value=self.installed):
            self.assertTrue(controller.credential_condition(expected,'heimdall')['credential_authority'])
            self.fixture.process(400,998,'/usr/bin/inert',[b'inert'],'/untracked.scope')
            with self.assertRaises(ValueError):controller.credential_condition(expected,'heimdall')

    def test_observer_process_cannot_be_misreported_as_active_bridge(self):
        self.native('heimdall',200)
        self.proof.listener('heimdall',self.installed)
        active=dict(self.installed,profile=dict(self.installed['profile'],validator={'phase':'active'}))
        with self.assertRaises(ValueError):self.proof.listener('heimdall',active)
        path=self.state.path('/proc/200/cmdline')
        path.write_bytes(path.read_bytes().replace(b'--bridge=false\0',b'--bridge=true\0--all\0'))
        self.proof.listener('heimdall',active)
        with self.assertRaises(ValueError):self.proof.listener('heimdall',self.installed)


if __name__=='__main__':unittest.main()

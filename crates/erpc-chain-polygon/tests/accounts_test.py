# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Reserved runtime authority and privileged paths; inert NSS/systemd only."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))


def fixture():
    spec=importlib.util.spec_from_file_location('polygon_account_fixture',ROOT/'tests/control.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    value=module.Lifecycle();value.setUp();return value


@unittest.skipUnless(os.name=='posix','managed NSS/POSIX state runs on the Linux host')
class Accounts(unittest.TestCase):
    def setUp(self):
        import accounts
        self.module=accounts;self.f=fixture();self.addCleanup(self.f.doCleanups)
        self.state=self.f.state;self.users=[];self.groups=[];self.extra={}
        self.account=accounts.Accounts(self.state,lambda:self.users,lambda:self.groups,lambda name,gid:[gid,*self.extra.get(name,[])])
        self.state.accounts=self.account
        def lookup(entries,field,value):
            match=next((entry for entry in entries if getattr(entry,field)==value),None)
            if match is None:raise KeyError(value)
            return match
        for module,name,entries,field in ((accounts.pwd,'getpwnam',lambda:self.users,'pw_name'),
                (accounts.pwd,'getpwuid',lambda:self.users,'pw_uid'),
                (accounts.grp,'getgrnam',lambda:self.groups,'gr_name'),
                (accounts.grp,'getgrgid',lambda:self.groups,'gr_gid')):
            mocked=patch.object(module,name,side_effect=lambda value,e=entries,f=field:lookup(e(),f,value))
            mocked.start();self.addCleanup(mocked.stop)
        original=self.state.run
        def run(args,**kwargs):
            if args[0]=='/usr/sbin/groupadd':
                record=self.account.record(self.f.contract);self.assertEqual(record['state'],'reserved')
                self.groups.append(SimpleNamespace(gr_name=args[-1],gr_gid=int(args[args.index('--gid')+1]),gr_mem=[]))
            if args[0]=='/usr/sbin/useradd':
                record=self.account.record(self.f.contract);self.assertEqual(record['state'],'reserved')
                self.users.append(SimpleNamespace(pw_name=args[-1],pw_uid=int(args[args.index('--uid')+1]),
                    pw_gid=int(args[args.index('--gid')+1]),pw_dir=args[args.index('--home-dir')+1],pw_shell=args[args.index('--shell')+1]))
            return original(args,**kwargs)
        self.state.run=run
        # Account creation occurs before native identities/history/units exist.
        for name in ('installed','identity','history','activation'):
            self.state.path('/etc/polygon/'+name+'.json').unlink(missing_ok=True)
        for name in ('/etc/credstore.encrypted/polygon','/var/lib/polygon/heimdall','/var/lib/polygon/bor'):
            directory=self.state.path(name)
            if directory.exists():shutil.rmtree(directory)
        self.state.path('/etc/credstore.encrypted/polygon').mkdir()
        for name in self.f.module.host.UNITS.values():self.state.path('/etc/systemd/system/'+name).unlink(missing_ok=True)

    def validator(self):
        self.f.contract=dict(self.f.contract,role='validator',signer='0x'+'1'*40,stake_owner='0x'+'2'*40)
        self.state.write('/etc/polygon/contract.json',dict(self.f.contract,runtime_protocol=3))
        storage=self.state.read('/etc/polygon/storage.json');storage['contract']=self.f.contract
        self.state.write('/etc/polygon/storage.json',storage)

    def test_validator_reserves_an_independent_original_broker_uid_and_retains_it_after_drift(self):
        self.validator();self.account.provision(self.f.contract)
        records=self.account.verify(self.f.contract)
        self.assertEqual(set(records),{'bor','heimdall','parent','broker'})
        self.assertEqual(records['broker'],{'uid':996,'gid':996})
        broker=next(user for user in self.users if user.pw_name=='polygon-rabbitmq')
        broker.pw_uid=2001
        with self.assertRaises(ValueError):self.account.verify(self.f.contract)
        self.assertEqual(self.account.retained_uids(),{996,997,998,999})
        self.assertEqual(self.account.retained_uids(('broker',)),{996})

    def test_validator_never_adopts_an_existing_broker_account_or_group(self):
        self.validator()
        self.groups.append(SimpleNamespace(gr_name='polygon-rabbitmq',gr_gid=2001,gr_mem=[]))
        before=len(self.f.calls)
        with self.assertRaises(ValueError):self.account.provision(self.f.contract)
        self.assertFalse(self.state.path(self.module.RECEIPT).exists());self.assertEqual(len(self.f.calls),before)
        self.groups.clear()
        self.users.append(SimpleNamespace(pw_name='polygon-rabbitmq',pw_uid=2001,pw_gid=2001,pw_dir='/home/old',pw_shell='/bin/bash'))
        with self.assertRaises(ValueError):self.account.provision(self.f.contract)
        self.assertFalse(self.state.path(self.module.RECEIPT).exists());self.assertEqual(len(self.f.calls),before)
    def test_unknown_existing_users_or_groups_never_become_our_reservation(self):
        for name,home in self.module.RULES.values():
            for kind in ('user','group'):
                self.users=[];self.groups=[]
                if kind=='user':self.users=[SimpleNamespace(pw_name=name,pw_uid=1001,pw_gid=1001,pw_dir='/home/previous',pw_shell='/bin/bash')]
                else:self.groups=[SimpleNamespace(gr_name=name,gr_gid=1001,gr_mem=[])]
                before=len(self.f.calls)
                with self.assertRaises(ValueError):self.f.control.dispatch(dict(self.f.request,action='reserve'))
                with self.assertRaises(ValueError):self.account.provision(self.f.contract)
                self.assertEqual(len(self.f.calls),before)
                self.assertFalse(self.state.path(self.module.RECEIPT).exists())
    def test_keyed_only_existing_names_refuse_before_reservation_or_nss(self):
        for module,name,value in ((self.module.pwd,'getpwnam',SimpleNamespace(pw_name='polygon-bor',pw_uid=2001,pw_gid=2001)),
                (self.module.grp,'getgrnam',SimpleNamespace(gr_name='polygon-bor',gr_gid=2001,gr_mem=[]))):
            with patch.object(module,name,return_value=value):
                before=len(self.f.calls)
                with self.assertRaises(ValueError):self.account.provision(self.f.contract)
                self.assertEqual(len(self.f.calls),before)
                self.assertFalse(self.state.path(self.module.RECEIPT).exists())

    def test_keyed_names_and_ids_must_agree_after_original_provisioning(self):
        self.account.provision(self.f.contract)
        foreign_user=SimpleNamespace(pw_name='polygon-bor',pw_uid=2001,pw_gid=2001,pw_dir='/home/foreign',pw_shell='/bin/bash')
        foreign_group=SimpleNamespace(gr_name='polygon-bor',gr_gid=2001,gr_mem=[])
        for module,name,value in ((self.module.pwd,'getpwnam',foreign_user),(self.module.pwd,'getpwuid',foreign_user),
                (self.module.grp,'getgrnam',foreign_group),(self.module.grp,'getgrgid',foreign_group)):
            with patch.object(module,name,return_value=value) as direct:
                with self.assertRaises(ValueError):self.account.verify(self.f.contract)
                self.assertGreater(direct.call_count,0)
                # Shutdown's retained IDs come from the receipt, not current NSS.
                self.assertEqual(self.account.retained_uids(),{997,998,999})
                self.assertEqual(self.account.retained_uids(('bor',)),{999})
                self.assertEqual(self.account.retained_uids(('heimdall',)),{998})
                self.assertEqual(self.account.retained_uids(('parent',)),{997})
                self.f.control.dispatch(dict(self.f.request,action='stop'))

    def test_retained_uid_scope_rejects_unknown_or_empty_component_sets(self):
        self.account.provision(self.f.contract)
        for selection in ((),('other',),('bor','other')):
            with self.assertRaises(ValueError):self.account.retained_uids(selection)
        self.assertEqual(self.account.retained_uids(('parent','heimdall')),{997,998})

    def test_first_condition_rejects_nss_or_numeric_recipient_drift_before_modeled_credential_grant(self):
        self.account.provision(self.f.contract)
        self.f.install_fixture();self.f.control.dispatch(dict(self.f.request,action='seal'));self.f.activate()
        grants=[]
        def condition(component):
            argv=['control.py','credential-condition',component,json.dumps(self.f.contract)]
            with patch.object(self.f.module.sys,'argv',argv),patch.object(self.f.module,'Control',return_value=self.f.control):
                self.f.module.main()
            # Models the separately source-qualified systemd 255 next phase.
            # No credential is decrypted and no real UID/ACL is changed here.
            grants.append(self.f.unit_recipients[self.f.module.host.UNITS[component]][0])
        for component,(name,_) in self.module.RULES.items():
            condition(component);before=len(grants)
            user=next(value for value in self.users if value.pw_name==name);original_uid=user.pw_uid
            user.pw_uid=2001
            with self.assertRaises(SystemExit) as error:condition(component)
            self.assertEqual(error.exception.code,255);self.assertEqual(len(grants),before)
            user.pw_uid=original_uid
            unit=self.f.module.host.UNITS[component];original=self.f.unit_recipients[unit]
            self.f.unit_recipients[unit]=(name,original[1])
            with self.assertRaises(SystemExit) as error:condition(component)
            self.assertEqual(error.exception.code,255);self.assertEqual(len(grants),before)
            self.f.unit_recipients[unit]=original
            condition(component)
        self.assertEqual(len(grants),6)

    def test_allocation_skips_keyed_only_numeric_owners_and_foreign_primary_gid(self):
        self.users=[SimpleNamespace(pw_name='unrelated',pw_uid=1001,pw_gid=999,pw_dir='/nonexistent',pw_shell='/usr/sbin/nologin')]
        user_lookup=self.module.pwd.getpwuid;group_lookup=self.module.grp.getgrgid
        def user(value):
            if value==999:return SimpleNamespace(pw_name='unlisted-user',pw_uid=999,pw_gid=1001)
            return user_lookup(value)
        def group(value):
            if value==998:return SimpleNamespace(gr_name='unlisted-group',gr_gid=998,gr_mem=[])
            return group_lookup(value)
        with patch.object(self.module.pwd,'getpwuid',side_effect=user),patch.object(self.module.grp,'getgrgid',side_effect=group):
            record=self.account.provision(self.f.contract)
            self.assertEqual(record['accounts']['bor'],{'uid':998,'gid':997})
            self.account.verify(self.f.contract)
            before=len(self.f.calls);self.account.provision(self.f.contract);self.assertEqual(len(self.f.calls),before)

    def test_unavailable_keyed_nss_is_never_treated_as_an_unused_identity(self):
        for module,name in ((self.module.pwd,'getpwnam'),(self.module.pwd,'getpwuid'),
                (self.module.grp,'getgrnam'),(self.module.grp,'getgrgid')):
            with patch.object(module,name,side_effect=OSError('inert NSS lookup failure')):
                before=len(self.f.calls)
                with self.assertRaises(OSError):self.account.provision(self.f.contract)
                self.assertFalse(self.state.path(self.module.RECEIPT).exists());self.assertEqual(len(self.f.calls),before)

    def test_one_durable_reservation_precedes_all_three_account_creations(self):
        self.f.control.dispatch(dict(self.f.request,action='provision-accounts'))
        value=self.account.verify(self.f.contract)
        self.assertEqual({item['uid'] for item in value.values()},{997,998,999})
        self.assertEqual(len({item['gid'] for item in value.values()}),3)
        self.assertEqual(self.state.path(self.module.RECEIPT).stat().st_mode&0o777,0o644)
        before=len(self.f.calls);self.account.provision(self.f.contract);self.assertEqual(len(self.f.calls),before)
    def test_failed_reservation_never_changes_nss(self):
        with patch.object(self.state,'write',side_effect=OSError('inert reservation sync failure')):
            with self.assertRaises(OSError):self.account.provision(self.f.contract)
        self.assertFalse(self.users);self.assertFalse(self.groups)
    def test_interrupted_account_creation_uses_original_reserved_ids(self):
        original=self.state.command;failed=[]
        def command(*args,**kwargs):
            result=original(*args,**kwargs)
            if args[0]=='/usr/sbin/useradd' and not failed:failed.append(True);raise OSError('inert useradd response loss')
            return result
        with patch.object(self.state,'command',side_effect=command):
            with self.assertRaises(OSError):self.account.provision(self.f.contract)
        reserved=copy.deepcopy(self.account.record(self.f.contract)['accounts'])
        self.assertEqual(len(self.users),1)
        self.account.provision(self.f.contract)
        self.assertEqual(self.account.verify(self.f.contract),reserved);self.assertEqual(len(self.users),3)
    def test_original_uid_gid_home_shell_and_membership_are_required_for_start(self):
        self.account.provision(self.f.contract);self.f.install_fixture();self.f.control.dispatch(dict(self.f.request,action='seal'));self.f.activate()
        saved_users=copy.deepcopy(self.users);saved_groups=copy.deepcopy(self.groups)
        for component,(name,home) in self.module.RULES.items():
            for kind in ('uid','gid','home','shell','supplementary','group-member','alias'):
                self.users=copy.deepcopy(saved_users);self.groups=copy.deepcopy(saved_groups);self.extra={}
                user=next(value for value in self.users if value.pw_name==name)
                if kind=='uid':user.pw_uid+=100
                elif kind=='gid':user.pw_gid+=100
                elif kind=='home':user.pw_dir='/home/previous'
                elif kind=='shell':user.pw_shell='/bin/bash'
                elif kind=='supplementary':self.extra[name]=[9988]
                elif kind=='group-member':next(value for value in self.groups if value.gr_name==name).gr_mem=['another-user']
                else:self.users.append(SimpleNamespace(**dict(vars(user),pw_name='unrelated')))
                with self.assertRaises(ValueError):self.f.control.runtime(self.f.contract,component)
                with self.assertRaises(ValueError):self.f.control.dispatch(dict(self.f.request,action='start-v2'))
                self.f.control.dispatch(dict(self.f.request,action='stop-v2'))
                self.assertFalse(self.f.running)
        self.f.control.dispatch(dict(self.f.request,action='destroy'))
    def test_legacy_without_original_receipt_can_stop_but_cannot_start_or_update(self):
        original=self.state.accounts;self.state.accounts=type('OldAccount',(),{'verify':lambda *_:{name:{'uid':uid,'gid':uid} for name,uid in [('bor',1001),('heimdall',1002),('parent',1003)]},'retained_uids':lambda *_:set()})()
        self.f.install_fixture();self.f.control.dispatch(dict(self.f.request,action='seal'));self.f.activate();self.state.accounts=original
        self.state.write('/etc/polygon/contract.json',self.f.contract)
        with self.assertRaises(ValueError):self.f.control.dispatch(dict(self.f.request,action='start-v2'))
        with self.assertRaises(ValueError):self.f.control.dispatch(dict(self.f.request,action='prepare',intent='d'*32))
        self.f.control.dispatch(dict(self.f.request,action='stop'))
        self.assertFalse(self.f.running)
    def test_owner_protocol_rejects_old_exact_contract_and_prevents_implicit_legacy_upgrade(self):
        stored=self.state.read('/etc/polygon/contract.json')
        self.assertEqual(stored,dict(self.f.contract,runtime_protocol=3))
        self.assertNotEqual(stored,self.f.contract)  # Older helpers compare this exact dictionary before mutation.
        self.state.ownership(self.f.contract)
        self.state.write('/etc/polygon/contract.json',self.f.contract)
        before=len(self.f.calls)
        with self.assertRaisesRegex(ValueError,'legacy runtime authority'):
            self.f.control.dispatch(dict(self.f.request,action='reserve'))
        with self.assertRaisesRegex(ValueError,'legacy runtime authority'):self.account.provision(self.f.contract)
        self.assertEqual(len(self.f.calls),before);self.assertFalse(self.users);self.assertFalse(self.groups)
        self.state.ownership(self.f.contract)  # Read-only scope/owned shutdown remains available.
        self.f.control.dispatch(dict(self.f.request,action='stop'))

    def test_lost_original_receipt_never_recreates_accounts_after_nss_loss(self):
        self.account.provision(self.f.contract)
        self.state.path(self.module.RECEIPT).unlink();self.users=[];self.groups=[]
        before=len(self.f.calls)
        with self.assertRaisesRegex(ValueError,'original runtime authority is missing'):self.account.provision(self.f.contract)
        self.assertEqual(len(self.f.calls),before)
        self.state.path(self.module.RESERVED).unlink()
        self.state.write('/etc/polygon/history.json',{'inert':'retained original history'})
        with self.assertRaisesRegex(ValueError,'original runtime authority is missing'):self.account.provision(self.f.contract)
        self.assertEqual(len(self.f.calls),before)

    def test_isolated_runtime_module_needs_no_sibling_import_search_path(self):
        import subprocess
        source=ROOT/'templates/scripts/accounts.py'
        program="import importlib.util,sys; sys.dont_write_bytecode=True; spec=importlib.util.spec_from_file_location('isolated_accounts',sys.argv[1]); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); assert callable(module.runtime)"
        result=subprocess.run([sys.executable,'-I','-c',program,str(source)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_actual_proxy_entry_refuses_group_drift_before_loading_credentials(self):
        import parent,resource
        self.account.provision(self.f.contract);record=self.account.record(self.f.contract);entry=record['accounts']['parent']
        with patch.object(parent.sys,'argv',['parent.py','sepolia']),patch.object(resource,'setrlimit'), \
                patch.object(Path,'read_text',return_value=json.dumps(record)), \
                patch.object(Path,'open',side_effect=AssertionError('credential file must remain unopened')), \
                patch.object(os,'getuid',return_value=entry['uid']),patch.object(os,'geteuid',return_value=entry['uid']), \
                patch.object(os,'getgid',return_value=entry['gid']),patch.object(os,'getegid',return_value=entry['gid']), \
                patch.object(os,'getgroups',return_value=[entry['gid'],9988]):
            with self.assertRaisesRegex(ValueError,'actual process privileges'):parent.main()

    def test_actual_native_entry_refuses_group_drift_before_exec(self):
        import launch
        self.account.provision(self.f.contract);record=self.account.record(self.f.contract);entry=record['accounts']['bor']
        def read(path,*args,**kwargs):return json.dumps(record if str(path)==self.module.RECEIPT else {'network':'amoy'})
        with patch.object(launch.sys,'argv',['launch.py','bor']),patch.object(Path,'read_text',side_effect=read,autospec=True), \
                patch.object(os,'getuid',return_value=entry['uid']),patch.object(os,'geteuid',return_value=entry['uid']), \
                patch.object(os,'getgid',return_value=entry['gid']),patch.object(os,'getegid',return_value=entry['gid']), \
                patch.object(os,'getgroups',return_value=[entry['gid'],9988]),patch.object(os,'execve') as execute:
            with self.assertRaisesRegex(ValueError,'actual process privileges'):launch.main()
            execute.assert_not_called()

    def test_actual_runtime_credentials_are_refused_for_other_uid_gid_or_extra_groups(self):
        self.account.provision(self.f.contract);record=self.account.record(self.f.contract)
        for component,entry in record['accounts'].items():
            network='sepolia' if component=='parent' else 'amoy'
            with patch.object(Path,'read_text',return_value=json.dumps(record)), \
                    patch.object(os,'getuid',return_value=entry['uid']),patch.object(os,'geteuid',return_value=entry['uid']), \
                    patch.object(os,'getgid',return_value=entry['gid']),patch.object(os,'getegid',return_value=entry['gid']):
                with patch.object(os,'getgroups',return_value=[entry['gid']]):self.module.runtime(component,network,parent=component=='parent')
                with patch.object(os,'getgroups',return_value=[entry['gid'],9988]):
                    with self.assertRaises(ValueError):self.module.runtime(component,network,parent=component=='parent')
                with patch.object(os,'getuid',return_value=0),patch.object(os,'getgroups',return_value=[]):
                    with self.assertRaises(ValueError):self.module.runtime(component,network,parent=component=='parent')


@unittest.skipUnless(os.name=='posix','managed paths use POSIX ownership')
class Namespaces(unittest.TestCase):
    def setUp(self):self.f=fixture();self.addCleanup(self.f.doCleanups);self.state=self.f.state
    def test_helper_firewall_custody_release_and_all_dropins_refuse_unsafe_ancestry(self):
        for logical in ('/usr/local/lib/erpc','/etc/credstore.encrypted','/opt/polygon/releases',
                '/etc/systemd/system/polygon-bor.service.d','/etc/systemd/system/erpc-polygon-firewall.service.d'):
            path=self.state.path(logical);path.mkdir(parents=True,exist_ok=True)
            old=path.with_name(path.name+'-old');path.rename(old)
            outside=self.state.path('/outside');outside.mkdir();outside.chmod(0o777)
            path.symlink_to(outside,target_is_directory=True)
            before=len(self.f.calls)
            with self.assertRaises(ValueError):self.f.control.dispatch(dict(self.f.request,action='reserve'))
            with self.assertRaises(ValueError):self.f.control.dispatch(dict(self.f.request,action='guard'))
            with self.assertRaises(ValueError):self.f.control.phase(self.f.request)
            self.assertEqual(len(self.f.calls),before);self.assertFalse(any(outside.iterdir()))
            path.unlink();old.rename(path);outside.rmdir()
            mode=path.stat().st_mode&0o777;path.chmod(0o777)
            with self.assertRaises(ValueError):self.state.namespaces()
            self.assertEqual(path.stat().st_mode&0o777,0o777);path.chmod(mode)
    def test_unknown_writable_or_linked_dropin_cannot_bypass_runtime_guards(self):
        for unit in (*self.f.module.host.UNITS.values(),'erpc-polygon-firewall.service'):
            directory=self.state.path('/etc/systemd/system/'+unit+'.d');directory.mkdir()
            path=directory/'override.conf';path.write_text('[Service]\nUser=root\n');path.chmod(0o666)
            with self.assertRaises(ValueError):self.state.namespaces()
            path.unlink();path.symlink_to(self.state.path('/etc/polygon/contract.json'))
            with self.assertRaises(ValueError):self.state.namespaces()
            shutil.rmtree(directory)
    def test_exact_owned_release_pointer_remains_supported(self):
        self.state.namespaces()
        pointer=self.state.path('/usr/local/lib/erpc/polygon/current')
        self.assertTrue(pointer.is_symlink())
        self.assertEqual(os.readlink(pointer),'/usr/local/lib/erpc/polygon/releases/'+self.f.control.helpers)

try:
    import ansible
    import yaml
    ANSIBLE=True
except ImportError:
    ANSIBLE=False


@unittest.skipUnless(ANSIBLE and os.name=='posix','publication integration requires pinned Ansible runtime')
class Publication(unittest.TestCase):
    def test_actual_reserve_guard_precedes_namespace_file_copy(self):
        import getpass
        import subprocess
        for kind in ('protected','ancestor-link','writable-parent','unsafe-dropin'):
            f=fixture()
            try:
                state=f.state;namespace=state.path('/usr/local/lib/erpc/polygon')
                outside=state.path('/outside');outside.mkdir()
                if kind=='ancestor-link':
                    namespace.rename(namespace.with_name('retained-original'));namespace.symlink_to(outside,target_is_directory=True)
                elif kind=='writable-parent':namespace.parent.chmod(0o777)
                elif kind=='unsafe-dropin':
                    dropin=state.path('/etc/systemd/system/polygon-bor.service.d');dropin.mkdir();(dropin/'override.conf').write_text('inert');(dropin/'override.conf').chmod(0o666)
                wrapper=state.path('/guard-fixture.py')
                wrapper.write_text('import os,sys,unittest; sys.dont_write_bytecode=True; from pathlib import Path; from types import SimpleNamespace; sys.path.insert(0,'+repr(str(ROOT/'templates/scripts'))+'); sys.path.insert(1,'+repr(str(ROOT/'tests'))+'); import control,volume_fixture; state=control.State(root=Path('+repr(str(state.root))+'),owner=os.getuid()); fixture=unittest.TestCase(); volume_fixture.attach(fixture,state); state.accounts=SimpleNamespace(preflight=lambda expected:None); control.Control(state,source=Path('+repr(str(f.source))+')).reserve('+repr(f.contract)+')')
                carried=state.path('/inert-source.py');carried.write_text('inert reviewed source')
                tasks=[{'ansible.builtin.command':{'argv':[sys.executable,'-I',str(wrapper)]}},
                    {'ansible.builtin.file':{'path':str(namespace),'state':'directory','owner':getpass.getuser(),'group':str(os.getgid()),'mode':'0755'}},
                    {'ansible.builtin.copy':{'src':str(carried),'dest':str(namespace/'published-fixture'),'owner':getpass.getuser(),'group':str(os.getgid()),'mode':'0644'}}]
                play=state.path('/publication.yml');play.write_text(yaml.safe_dump([{'hosts':'all','gather_facts':False,'tasks':tasks}]))
                result=subprocess.run([sys.executable,'-I','-m','ansible.cli.playbook','-i','localhost,','-c','local',str(play)],capture_output=True,text=True)
                if kind=='protected':
                    self.assertEqual(result.returncode,0,result.stdout+result.stderr);self.assertTrue((namespace/'published-fixture').is_file())
                else:
                    self.assertNotEqual(result.returncode,0);self.assertFalse((namespace/'published-fixture').exists())
                    if kind=='ancestor-link':self.assertTrue(namespace.is_symlink());self.assertFalse(any(outside.iterdir()))
                    if kind=='writable-parent':self.assertEqual(namespace.parent.stat().st_mode&0o777,0o777)
            finally:f.doCleanups()

if __name__=='__main__':unittest.main()

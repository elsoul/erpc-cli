# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real ingress receipt/config/unit files, with inert NSS, ownership and service effects."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'templates/node'))
import native_gateway as gateway
import native_files as files
import native_state as lifecycle
from mounts import owner


class Gateway(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);self.addCleanup(patch.stopall)
        self.root=Path(temporary.name)
        self.directory=self.root/'state';self.directory.mkdir()
        self.contract=owner();self.contract.update(profile='agave-native-rpc',vote_account=None,authority_account=None)
        patch.object(lifecycle,'read',lambda path,size:files.read(path,size,os.getuid())).start()
        patch.object(gateway,'read',lambda path,size=1048576:files.read(path,size,os.getuid())).start()
        patch.object(gateway,'sync_file',lambda path:files.sync_file(path,os.getuid())).start()
        def directory(path,create=False):
            if create:path.mkdir(parents=True,exist_ok=True)
            if path.is_symlink() or not path.is_dir() or path.stat().st_mode&0o022:raise ValueError('inert unsafe directory')
        patch.object(gateway,'root_directory',directory).start()
        for name,relative in [('UNITS','units'),('CONFIG','config/ingress.conf'),('BINARY','bin/nginx'),('RUN','run/ingress')]:
            path=self.root/relative;path.parent.mkdir(parents=True,exist_ok=True)
            if name=='UNITS':path.mkdir()
            patch.object(gateway,name,path).start()
        gateway.BINARY.write_bytes(b'inert packaged executable, never run');gateway.BINARY.chmod(0o555)
        self.account={'name':'erpc-solana-gateway','home':'/var/lib/erpc-solana-gateway','shell':'/usr/sbin/nologin','uid':20004,'gid':20004}
        self.identity=patch.object(gateway.identities,'verify',return_value=self.account).start()
        patch.object(gateway.helpers,'verify',return_value=self.root).start()
        self.quiet=patch.object(gateway.processes,'assert_quiescent').start()
        self.state=lifecycle.State(self.directory);self.state.reserve(self.contract)
        self.state.put(gateway.identities.RECEIPT,{'contract':self.contract,'accounts':{'gateway':self.account}})
        self.state.put('gateway-distribution.json',{'contract':self.contract,'unit':'nginx.service'})
        (gateway.UNITS/'nginx.service').symlink_to('/dev/null')
        self.distribution={'LoadState':'masked','ActiveState':'inactive','MainPID':'0','FragmentPath':'/dev/null','DropInPaths':'','UnitFileState':'masked'}
        self.intent='a'*32;self.revision='b'*64
        self.state.authorize(self.contract,self.intent,{'mode':'rpc','helper_revision':self.revision},'deploy')
        self.state.begin(self.contract,self.intent,lambda:None)
        self.access={'controller':'192.0.2.2','ssh_port':22,'management':[],'rpc':['198.51.100.8/32','2001:db8:1::/64']}
        self.state.put('firewall-preparation-'+self.intent+'.json',{'contract':self.contract,'intent':self.intent,
            'helper_revision':self.revision,'access':self.access})
        self.calls=[];self.commands=[];self.running=False;self.skip=False
        original=Path.lstat;self.owners={}
        def metadata(path,*args,**kwargs):
            result=original(path,*args,**kwargs)
            if path==gateway.RUN:
                result=list(result);result[4],result[5]=self.owners.get(path,(0,0));result=os.stat_result(result)
            if path==gateway.UNITS/'nginx.service':
                result=list(result);result[4]=0;result=os.stat_result(result)
            return result
        patch.object(Path,'lstat',metadata).start()
        patch.object(gateway.os,'chown',lambda path,uid,gid,**kwargs:self.owners.__setitem__(path,(uid,gid))).start()

    def systemctl(self,args,**kwargs):
        self.calls.append(args)
        if args[0]=='show':
            if args[1]=='nginx.service':return ''.join(k+'='+v+'\n' for k,v in self.distribution.items())
            if args[-2:]==['--property=LoadState','--value']:return 'not-found\n'
            return ''.join(k+'='+v+'\n' for k,v in {'LoadState':'loaded','FragmentPath':str(gateway.UNITS/gateway.UNIT),
                'DropInPaths':'','User':'20004','Group':'20004','NeedDaemonReload':'no',
                'ActiveState':'active' if self.running else 'inactive','SubState':'running' if self.running else 'dead',
                'MainPID':'333' if self.running else '0'}.items())
        if args[0]=='stop':self.running=False
        if args[0]=='start' and not self.skip:self.running=True
        return ''

    def install(self):
        def command(args):
            self.commands.append(args)
            if args[0]=='/usr/bin/setpriv':
                # All compiled HTTP modules register their temporary paths even
                # when no location uses them. Model a fresh distro installation
                # whose /var/lib/nginx children have never been created by root.
                text=gateway.CONFIG.read_text()
                directives={line.strip().split()[0]:line.strip().split()[1].rstrip(';')
                            for line in text.splitlines() if '_temp_path ' in line}
                expected={'client_body_temp_path','proxy_temp_path','fastcgi_temp_path','scgi_temp_path','uwsgi_temp_path'}
                if set(directives)!=expected or any(Path(value).parent!=gateway.RUN for value in directives.values()):
                    raise PermissionError('unprivileged nginx cannot create distribution default temp directories')
            return '1.24.0-2ubuntu7.5' if args[0]=='/usr/bin/dpkg-query' else ''
        return gateway.install(self.state,self.contract,self.intent,self.revision,self.systemctl,
            command)

    def test_install_validates_as_original_uid_and_starts_without_any_native_key(self):
        receipt=self.install()
        self.assertEqual(self.commands[-1][:7],['/usr/bin/setpriv','--reuid','20004','--regid','20004','--clear-groups','--no-new-privs'])
        self.assertEqual(self.commands[-1][-1],'-t')
        config=gateway.CONFIG.read_text();unit=(gateway.UNITS/gateway.UNIT).read_text()
        for text in ['listen 0.0.0.0:7211','listen [::]:7212','allow 198.51.100.8/32','allow 2001:db8:1::/64','deny all;','proxy_http_version 1.1','proxy_set_header Upgrade $http_upgrade']:
            self.assertIn(text,config)
        self.assertNotIn('LoadCredential',unit);self.assertNotIn('master_process off',config)
        self.assertEqual(gateway.verify(self.state,self.contract,receipt),self.account)
        self.assertEqual(gateway.start(self.state,self.contract,receipt,self.systemctl),333)
        gateway.shutdown(self.state,self.contract,self.systemctl);self.assertFalse(self.running)
        self.assertTrue(gateway.CONFIG.exists());self.assertTrue((self.directory/'gateway-install.json').exists())

    def test_interrupted_publication_retries_original_receipt_and_rejects_foreign_config(self):
        gateway.CONFIG.write_bytes(b'unowned configuration')
        with self.assertRaisesRegex(ValueError,'unknown ingress configuration'):self.install()
        self.assertEqual(gateway.CONFIG.read_bytes(),b'unowned configuration');gateway.CONFIG.unlink()
        real=gateway.atomic
        def fail(path,raw,*args):
            if path==gateway.UNITS/gateway.UNIT:raise OSError('inert unit publication failure')
            return real(path,raw,*args)
        with patch.object(gateway,'atomic',fail),self.assertRaises(OSError):self.install()
        self.assertFalse(any(args[0]=='/usr/bin/setpriv' for args in self.commands))
        receipt=self.install();gateway.verify(self.state,self.contract,receipt)
        self.assertTrue((self.directory/'cutover.json').exists())

    def test_named_account_drift_prevents_start_but_owned_stop_still_works(self):
        receipt=self.install();self.running=True
        self.identity.side_effect=ValueError('inert NSS drift')
        with self.assertRaises(ValueError):gateway.start(self.state,self.contract,receipt,self.systemctl)
        gateway.shutdown(self.state,self.contract,self.systemctl)
        self.assertFalse(self.running);self.quiet.assert_called_with(20004)

    def test_changed_binary_skipped_condition_and_unknown_overrides_are_not_success(self):
        receipt=self.install();self.skip=True
        with self.assertRaisesRegex(ValueError,'did not start'):gateway.start(self.state,self.contract,receipt,self.systemctl)
        gateway.BINARY.chmod(0o755);gateway.BINARY.write_bytes(b'changed distribution binary')
        with self.assertRaisesRegex(ValueError,'binary changed'):gateway.verify(self.state,self.contract,receipt)
        override=gateway.UNITS/(gateway.UNIT+'.d');override.mkdir();(override/'foreign.conf').write_bytes(b'unknown override')
        with self.assertRaisesRegex(ValueError,'unknown service override'):gateway.shutdown(self.state,self.contract,self.systemctl)

    def test_stop_failure_still_disables_and_keeps_custody_and_data_untouched(self):
        self.install();self.running=True;original=self.systemctl
        def fail(args,**kwargs):
            if args[0]=='stop':self.calls.append(args);raise ValueError('inert stop failure')
            return original(args,**kwargs)
        with self.assertRaises(ValueError):gateway.shutdown(self.state,self.contract,fail)
        self.assertIn(['disable',gateway.UNIT],self.calls)
        self.assertTrue((self.directory/'gateway-install.json').exists())

    def test_interrupted_empty_runtime_directory_is_recoverable_but_unknown_data_is_not(self):
        with patch.object(gateway.os,'chown',side_effect=OSError('inert ownership failure')):
            with self.assertRaises(OSError):self.install()
        marker=gateway.RUN/'unowned';marker.write_bytes(b'retain')
        with self.assertRaisesRegex(ValueError,'not empty'):self.install()
        self.assertEqual(marker.read_bytes(),b'retain');marker.unlink()
        receipt=self.install();gateway.verify(self.state,self.contract,receipt)
        self.assertEqual(self.owners[gateway.RUN],(20004,20004))

    def test_fresh_package_requires_preexisting_suppression_and_refuses_foreign_service(self):
        marker=self.directory/'gateway-distribution.json';marker.unlink()
        mask=gateway.UNITS/'nginx.service';mask.unlink()
        self.distribution.update(LoadState='not-found',FragmentPath='',UnitFileState='')
        self.assertTrue(gateway.package(self.state,self.contract,self.systemctl,prepare=True)['suppression_reserved'])
        with self.assertRaises(ValueError):gateway.package(self.state,self.contract,self.systemctl)
        mask.symlink_to('/dev/null');self.distribution.update(LoadState='masked',FragmentPath='/dev/null',UnitFileState='masked')
        gateway.package(self.state,self.contract,self.systemctl)
        for key,value in [('ActiveState','active'),('MainPID','44'),('DropInPaths','/etc/systemd/system/nginx.service.d/custom.conf'),('FragmentPath','/etc/systemd/system/foreign.service')]:
            original=self.distribution[key];self.distribution[key]=value
            with self.assertRaises(ValueError):gateway.package(self.state,self.contract,self.systemctl,prepare=True)
            self.distribution[key]=original
        mask.unlink();mask.write_text('[Service]\nExecStart=/inert/unmanaged\n')
        with self.assertRaises(ValueError):gateway.package(self.state,self.contract,self.systemctl,prepare=True)
        self.assertIn('unmanaged',mask.read_text())
        self.assertTrue(all(call[0]=='show' for call in self.calls))

    def test_unmask_after_install_prevents_native_gateway_start_and_receipt_validation(self):
        receipt=self.install();self.calls.clear()
        (gateway.UNITS/'nginx.service').unlink()
        self.distribution.update(LoadState='loaded',FragmentPath='/usr/lib/systemd/system/nginx.service',UnitFileState='enabled')
        with self.assertRaises(ValueError):gateway.start(self.state,self.contract,receipt,self.systemctl)
        with self.assertRaises(FileNotFoundError):gateway.verify(self.state,self.contract,receipt)
        self.assertFalse(any(call[0]=='start' for call in self.calls))


if __name__=='__main__':unittest.main()

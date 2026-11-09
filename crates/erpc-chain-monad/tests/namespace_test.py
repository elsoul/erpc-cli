# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real inert file publication with modeled root UID; no NSS, device or host action."""
import os
import io
from pathlib import Path
import stat
import sys
import tempfile
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parents[1]/'templates/node'))
import erpc_monad_common as common
import erpc_monad_namespace as ns
import erpc_monad_package as package


class Namespace(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name).resolve();self.root.chmod(0o755)
        self.addCleanup(self.tmp.cleanup)
        self.patches=[]
        def install(obj,name,value):
            handle=patch.object(obj,name,value);handle.start();self.patches.append(handle)
        self.addCleanup(lambda:[item.stop() for item in reversed(self.patches)])
        self.real_lstat=os.lstat;self.real_scandir=os.scandir;self.foreign=set()
        def metadata(path,*args,**kwargs):
            info=list(self.real_lstat(path,*args,**kwargs));candidate=Path(path)
            if candidate==self.root or self.root in candidate.parents:
                if info[4]==os.getuid():info[4]=0
                if candidate in self.foreign:info[4]=2
            elif candidate in self.root.parents:
                info[4]=0;info[0]&=~0o022;info[0]|=0o001
            return os.stat_result(info)
        def scan(path):
            class Entries(list):
                def __enter__(self):return iter(self)
                def __exit__(self,*_):return False
            with self.real_scandir(path) as rows:
                return Entries(SimpleNamespace(name=row.name,path=row.path,
                    stat=lambda *,follow_symlinks=True,p=row.path:metadata(p)) for row in rows)
        install(os,'lstat',metadata);install(Path,'lstat',metadata);install(os,'scandir',scan)
        for name,path in [('ROOT','state'),('CONFIG','config'),('HELPERS','lib/helpers'),('RELEASES','release'),
                          ('SYSTEMD','units'),('FIREWALL','lib/rpc-firewall.py'),('UDEV','udev/monad.rules'),('SYSCTL','sysctl/monad.conf')]:
            install(ns,name,self.root/path)
        for path in (ns.ROOT,ns.CONFIG,ns.RELEASES,ns.SYSTEMD,ns.HELPERS.parent,ns.UDEV.parent,ns.SYSCTL.parent):path.mkdir(parents=True,exist_ok=True)
        install(ns,'read',lambda path:common.read(path,owner=os.getuid()))
        self.source=Path(__file__).parents[1]/'templates/node'

    def test_empty_foreign_writable_linked_and_private_helper_ancestors_refuse_without_repair(self):
        ns.fresh()
        for path in (ns.ROOT,ns.CONFIG,ns.HELPERS.parent,ns.RELEASES,ns.SYSTEMD):
            with self.subTest(path=path):
                before=path.stat().st_mode
                path.chmod(0o777)
                with self.assertRaises(ValueError):ns.fresh()
                self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o777)
                path.chmod(stat.S_IMODE(before));self.foreign.add(path)
                with self.assertRaises(ValueError):ns.fresh()
                self.foreign.remove(path)
        ns.HELPERS.parent.chmod(0o700)
        with self.assertRaises(ValueError):ns.paths()
        ns.HELPERS.parent.chmod(0o755)
        moved=self.root/'original-lib';ns.HELPERS.parent.rename(moved);ns.HELPERS.parent.symlink_to(moved)
        with self.assertRaises(ValueError):ns.paths()

    def test_boot_overrides_receipt_links_and_common_source_are_checked_before_use(self):
        directory=ns.SYSTEMD/(ns.UNITS[0]+'.d');directory.mkdir()
        unknown=directory/'99-override.conf';unknown.write_bytes(b'inert override')
        for mode in (0o644,0o666):
            unknown.chmod(mode)
            with self.assertRaises(ValueError):ns.paths()
            self.assertEqual(unknown.read_bytes(),b'inert override')
        unknown.unlink();directory.rmdir()
        owner=ns.ROOT/'owner.json';common.atomic(owner,b'{}')
        ns.paths();owner.chmod(0o644)
        with self.assertRaises(ValueError):ns.paths()
        owner.chmod(0o600);os.link(owner,self.root/'alias')
        with self.assertRaises(ValueError):ns.paths()
        (self.root/'alias').unlink()
        ns.FIREWALL.write_bytes(b'inert standalone source');ns.FIREWALL.chmod(0o666)
        with self.assertRaises(ValueError):ns.paths()
        self.assertEqual(ns.FIREWALL.read_bytes(),b'inert standalone source')

    def test_real_publication_under_umask077_retries_and_checks_exact_sealed_bytes(self):
        ns.fresh();real=os.replace;count=[0]
        def interrupted(source,destination):
            count[0]+=1
            if count[0]==3:raise OSError('inert interrupted publication')
            return real(source,destination)
        old=os.umask(0o077)
        try:
            with patch.object(os,'replace',interrupted),self.assertRaises(OSError):ns.publish(self.source)
            ns.publish(self.source)
        finally:os.umask(old)
        self.assertEqual(set(path.name for path in ns.HELPERS.iterdir()),set(ns.FILES))
        self.assertEqual(stat.S_IMODE(ns.HELPERS.stat().st_mode),0o755)
        for name in ns.FILES:
            self.assertEqual((ns.HELPERS/name).read_bytes(),(self.source/name).read_bytes())
            self.assertEqual(stat.S_IMODE((ns.HELPERS/name).stat().st_mode),0o644)
        ns.paths()
        extra=ns.HELPERS/'unknown.py';extra.write_bytes(b'inert unknown root-only source')
        with self.assertRaises(ValueError):ns.publish(self.source)
        self.assertEqual(extra.read_bytes(),b'inert unknown root-only source')

    def test_shutdown_namespace_does_not_depend_on_private_credential_health(self):
        cipher=ns.CONFIG/'monad-secp.cred';cipher.write_bytes(b'inert broken custody');cipher.chmod(0o666)
        with self.assertRaises(ValueError):ns.paths()
        ns.paths(runtime=False)
        self.assertEqual(cipher.read_bytes(),b'inert broken custody')

    def test_fresh_managed_unit_or_kernel_rule_is_not_adopted(self):
        for path in (ns.SYSTEMD/ns.UNITS[0],ns.UDEV,ns.SYSCTL):
            path.write_bytes(b'inert previous authority')
            with self.assertRaises(ValueError):ns.fresh()
            self.assertEqual(path.read_bytes(),b'inert previous authority');path.unlink()

    def test_cached_bootstrap_directory_is_valid_without_weakening_private_files(self):
        directory=ns.ROOT/'bootstrap';directory.mkdir(mode=0o700)
        for name in ('receipt.json','node.toml','forkpoint.toml','validators.toml'):
            common.atomic(directory/name,b'inert cached original bootstrap')
        ns.paths();ns.paths(runtime=False)
        path=directory/'node.toml';path.chmod(0o666)
        with self.assertRaises(ValueError):ns.paths()
        ns.paths(runtime=False)  # Damaged bootstrap is not shutdown authority.
        path.chmod(0o600);outside=self.root/'bootstrap-alias';os.link(path,outside)
        with self.assertRaises(ValueError):ns.paths()
        outside.unlink();common.atomic(directory/'unknown',b'inert')
        with self.assertRaises(ValueError):ns.paths()

    def test_actual_extracted_library_aliases_match_receipt_and_remain_one_hop(self):
        archive=io.BytesIO()
        with tarfile.open(fileobj=archive,mode='w') as tar:
            for name in package.BINARIES:
                item=tarfile.TarInfo('usr/local/bin/'+name);item.size=5
                tar.addfile(item,io.BytesIO(b'inert'))
            item=tarfile.TarInfo('usr/local/lib/libfixture.so.1');item.size=5
            tar.addfile(item,io.BytesIO(b'inert'))
            item=tarfile.TarInfo('usr/local/lib/libfixture.so');item.type=tarfile.SYMTYPE
            item.linkname='libfixture.so.1';tar.addfile(item)
        partial=ns.RELEASES/'0.16.5.partial';partial.mkdir(mode=0o700)
        payload=partial/'payload';payload.mkdir(mode=0o700)
        process=SimpleNamespace(stdout=io.BytesIO(archive.getvalue()),wait=lambda **_:0,poll=lambda:0)
        with patch.object(package.subprocess,'Popen',return_value=process):package.extract(partial/'inert',payload)
        ns.paths()  # Interrupted authenticated extraction, before receipt.
        common.atomic(payload/'receipt.json',common.json_bytes(package.receipt(payload)))
        final=ns.RELEASES/'0.16.5';payload.rename(final);partial.rmdir()
        ns.paths();ns.paths(runtime=False)
        alias=final/'lib/libfixture.so';original=os.readlink(alias)
        for target in ('../bin/monad','/etc/passwd','libfixture.so'):
            alias.unlink();alias.symlink_to(target)
            with self.assertRaises((ValueError,OSError)):ns.paths()
        alias.unlink();alias.symlink_to(original)
        (final/'lib/libfixture.so.1').chmod(0o666)
        with self.assertRaises(ValueError):ns.paths()
        (final/'lib/libfixture.so.1').chmod(0o444)
        common.atomic(final/'receipt.json',common.json_bytes({'files':{},'links':{}}))
        with self.assertRaises(ValueError):ns.paths()


if __name__=='__main__':unittest.main()

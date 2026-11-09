#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert ELF bytes, open descriptors and disk/cancellation failure injection."""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import native_publish as publish


def elf_bytes():
    header = bytearray(64)
    header[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH', header, 16, 3, 62)
    return bytes(header) + b'inert executable-shaped public fixture, never executed'


class Publication(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / 'candidate'
        self.content = elf_bytes()
        self.source.write_bytes(self.content)
        self.source.chmod(0o700)
        self.expected = {'size': len(self.content), 'sha256': hashlib.sha256(self.content).hexdigest()}

    def tearDown(self):
        # Read-only public files remain removable from their owned parent.
        self.temporary.cleanup()

    def test_existing_builder_write_descriptor_cannot_modify_the_published_inode(self):
        destination = self.root / 'published'
        writer = os.open(self.source, os.O_WRONLY)
        previous = os.umask(0o077)
        try:
            publish.copy_binary(self.source, destination, self.expected, os.geteuid())
            os.write(writer, b'changed old builder inode')
        finally:
            os.umask(previous)
            os.close(writer)
        self.assertEqual(destination.read_bytes(), self.content)
        self.assertNotEqual(destination.stat().st_ino, self.source.stat().st_ino)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o555)

    def test_links_foreign_owner_setuid_and_changed_digest_are_refused(self):
        link = self.root / 'link'; link.symlink_to(self.source)
        with self.assertRaises(OSError):
            publish.copy_binary(link, self.root / 'bad-link', self.expected, os.geteuid())
        with self.assertRaises(ValueError):
            publish.copy_binary(self.source, self.root / 'bad-owner', self.expected, os.geteuid()+1)
        self.source.chmod(0o4700)
        with self.assertRaises(ValueError):
            publish.copy_binary(self.source, self.root / 'bad-setuid', self.expected, os.geteuid())
        self.source.chmod(0o700)
        with self.assertRaises(ValueError):
            publish.copy_binary(self.source, self.root / 'bad-digest', dict(self.expected,sha256='0'*64), os.geteuid())
        os.link(self.source, self.root / 'alias')
        with self.assertRaises(ValueError):
            publish.copy_binary(self.source, self.root / 'bad-hardlink', self.expected, os.geteuid())

    def test_file_fsync_failure_is_not_reported_as_success(self):
        with patch.object(publish.os, 'fsync', side_effect=OSError('inert disk failure')):
            with self.assertRaises(OSError):
                publish.copy_binary(self.source, self.root/'incomplete', self.expected, os.geteuid())

    def fixture(self):
        intent = 'a'*32
        work = self.root/'work'; (work/'output/bin').mkdir(parents=True)
        (work/'output/bin/agave-validator').write_bytes(self.content)
        profile = {'commit':'b'*40,'cargo_lock_sha256':'c'*64,'rust':'1.97.1','version':'4.3.2'}
        public = {'schema':1,'intent':intent,'network':'mainnet','commit':profile['commit'],
                  'version':profile['version'],'catalog_sha256':'d'*64}
        catalog = {'networks':{'mainnet':profile},'publish_binaries':['agave-validator']}
        result = {'request':public,'source':{key:profile[key] for key in ('commit','cargo_lock_sha256','rust')},
                  'files':{'agave-validator':self.expected}}
        (work/'build-result.json').write_text(json.dumps(result))
        return intent,work,public,catalog,result

    @unittest.skipIf(os.geteuid()==0, 'builder fixture must be unprivileged')
    def test_publication_checks_quiescence_and_intent_again_before_directory_commit(self):
        intent,work,public,catalog,result=self.fixture()
        releases=self.root/'releases';releases.mkdir()
        state=Mock();state.current.side_effect=[{'target':public}, ValueError('cancelled during publication')]
        quiescent=Mock()
        # Linux root ownership is a platform acceptance test; this fixture only
        # substitutes the parent authority check, not copying or fsync behavior.
        with patch.object(publish,'RELEASES',releases),patch.object(publish,'root_directory'),patch.object(publish,'verify') as verify:
            with self.assertRaisesRegex(ValueError,'cancelled'):
                publish.publish(state,{'network':'mainnet'},intent,work,public,catalog,os.geteuid(),quiescent)
            verify.assert_not_called()
        self.assertFalse((releases/intent).exists())
        self.assertEqual(quiescent.call_count,2)
        stages=list(releases.glob('.stage-*'))
        self.assertEqual(len(stages),1)
        self.assertEqual(stat.S_IMODE(stages[0].stat().st_mode),0o700)

    @unittest.skipIf(os.geteuid()==0, 'builder fixture must be unprivileged')
    def test_receipt_does_not_substitute_another_network_source_or_artifact_set(self):
        intent,work,public,catalog,result=self.fixture()
        self.assertEqual(publish.qualified_result(work,public,catalog,os.geteuid()),result)
        for altered in [dict(result,request=dict(public,network='testnet')),
                        dict(result,source=dict(result['source'],commit='e'*40)),
                        dict(result,files={'unexpected':self.expected}),
                        dict(result,files={'agave-validator':dict(self.expected,size=True)})]:
            (work/'build-result.json').write_text(json.dumps(altered))
            with self.assertRaises(ValueError):
                publish.qualified_result(work,public,catalog,os.geteuid())
        (work/'output/bin').rename(work/'saved')
        (work/'output/bin').symlink_to(work/'saved')
        with self.assertRaises(ValueError):
            publish.qualified_result(work,public,catalog,os.geteuid())


if __name__=='__main__':unittest.main()

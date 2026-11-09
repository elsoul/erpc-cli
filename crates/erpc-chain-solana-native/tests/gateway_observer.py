# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert proc files and public RFC handshake vectors; no socket or nginx execution."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'templates/node'))
import native_gateway_observer as observe
import native_gateway as gateway
import runtime_process as fixture


class IngressObserver(unittest.TestCase):
    def setUp(self):
        self.inner=fixture.RuntimeProcess();self.inner.setUp();self.addCleanup(self.inner.doCleanups)
        self.master=self.inner.directory;self.worker=self.inner.process(456,self.inner.uid)
        item=patch.object(gateway,'BINARY',self.inner.binary);item.start();self.addCleanup(item.stop)
        for directory,title in [(self.master,'nginx: master process '+' '.join(gateway.arguments())),(self.worker,'nginx: worker process')]:
            (directory/'cgroup').write_bytes(observe.CGROUP)
            (directory/'cmdline').write_bytes(title.encode()+b'\0'*8)
            if not (directory/'exe').exists():(directory/'exe').symlink_to(self.inner.binary)
        for number,inode in [(5,1003),(6,1004)]:
            (self.master/'fd'/str(number)).symlink_to('socket:['+str(inode)+']')
        for name,address,inodes in [('tcp','0'*8,[1001,1002]),('tcp6','0'*32,[1003,1004])]:
            (self.master/'net'/name).write_text(self.inner.header+''.join(
                self.inner.record(port,inode,address=address) for port,inode in zip([7211,7212],inodes)))
        self.account={'uid':self.inner.uid,'gid':self.inner.gid}

    def prove(self):return observe.prove(self.inner.pid,self.account)

    def test_master_workers_and_both_dual_stack_listeners_are_proven(self):
        self.assertEqual(self.prove(),((123,90210),(456,90210)))
        (self.master/'fd/6').unlink()
        with self.assertRaises(ValueError):self.prove()

    def test_foreign_worker_command_orphan_and_duplicate_socket_refuse(self):
        command=self.worker/'cmdline';original=command.read_bytes()
        command.write_bytes(b'nginx: worker process with arbitrary config\0')
        with self.assertRaisesRegex(ValueError,'invocation'):self.prove()
        command.write_bytes(original);(self.worker/'cgroup').write_bytes(b'0::/other.scope\n')
        with self.assertRaisesRegex(ValueError,'orphan'):self.prove()
        (self.worker/'cgroup').write_bytes(observe.CGROUP)
        table=self.master/'net/tcp';table.write_text(table.read_text()+self.inner.record(7211,1001,address='0'*8))
        with self.assertRaisesRegex(ValueError,'duplicate'):self.prove()

    def test_changed_process_family_during_listener_inspection_refuses(self):
        original=observe.listeners
        def changed(*args):
            original(*args)
            path=self.worker/'stat';path.write_text(path.read_text().replace('90210','90211'))
        with patch.object(observe,'listeners',changed),self.assertRaisesRegex(ValueError,'changed'):
            self.prove()


class WebsocketHandshake(unittest.TestCase):
    def check(self,raw):
        class Stream:
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def sendall(self,value):self.requests.append(value)
            def settimeout(self,value):self.timeout=value
            def recv(self,size):
                value=self.data[:size];self.data=self.data[size:];return value
        stream=Stream();stream.data=raw;stream.requests=[]
        calls=[]
        # Published RFC 6455 vector, supplied only at the nonce boundary.
        observe.websocket(lambda address,timeout:(calls.append((address,timeout)) or stream),
                          lambda size:b'the sample nonce' if size==16 else bytes([1,2,3,4]))
        self.assertEqual(calls,[(('127.0.0.1',7212),5)])
        self.assertIn(b'Sec-WebSocket-Version: 13',stream.requests[0])
        self.assertEqual(stream.requests[1],bytes([136,128,1,2,3,4]))

    def test_only_the_public_rfc_upgrade_is_accepted(self):
        valid=(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
               b'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n')
        self.check(valid)
        for bad in [valid.replace(b'101',b'200'),valid.replace(b's3pPL',b'wrong'),
                    valid.replace(b'\r\n\r\n',b'\r\nUpgrade: websocket\r\n\r\n'),
                    valid.replace(b'\r\n\r\n',b'\r\nSec-WebSocket-Protocol: unknown\r\n\r\n'),
                    valid.replace(b'\r\n\r\n',b'\r\nSec-WebSocket-Extensions: unknown\r\n\r\n'),
                    b'HTTP/1.1 101\r\n'+b'x'*17000,b'']:
            with self.assertRaises(ValueError):self.check(bad)


if __name__=='__main__':unittest.main()

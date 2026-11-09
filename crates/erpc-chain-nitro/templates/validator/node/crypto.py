# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Public Ethereum signature recovery through the OS libsecp256k1 ABI.

No signing API is exposed here. Ubuntu24.04 libsecp256k1-1 (upstream v0.2.0)
provides the recovery module. Its opaque signature/public-key sizes, context
flag1 and uncompressed flag2 come from the qualified public C headers.
"""
import ctypes
import os
from pathlib import Path
import re
import stat
from storage import ROOT_UID, directory, read, require

LIBRARY = Path('/usr/lib/x86_64-linux-gnu/libsecp256k1.so.1')
ORDER = int('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16)


def keccak(value):
    # Ubuntu's python3-pycryptodome installs the Cryptodome namespace.
    from Cryptodome.Hash import keccak as implementation
    return implementation.new(digest_bits=256, data=value).digest()


def load():
    directory(LIBRARY.parent)
    path = LIBRARY
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        require(info.st_uid == ROOT_UID, 'untrusted OS cryptographic library selector')
        target = os.readlink(path)
        require(re.fullmatch(r'libsecp256k1\.so\.1\.[0-9]+\.[0-9]+', target),
                'OS cryptographic library selector left its fixed ABI namespace')
        path = path.parent / target
    read(path, 8 * 1024 * 1024)
    library = ctypes.CDLL(str(path), mode=os.RTLD_LOCAL | os.RTLD_NOW)
    library.secp256k1_context_create.argtypes = [ctypes.c_uint]
    library.secp256k1_context_create.restype = ctypes.c_void_p
    library.secp256k1_context_destroy.argtypes = [ctypes.c_void_p]
    library.secp256k1_context_destroy.restype = None
    library.secp256k1_ecdsa_recoverable_signature_parse_compact.argtypes = [ctypes.c_void_p] * 3 + [ctypes.c_int]
    library.secp256k1_ecdsa_recoverable_signature_parse_compact.restype = ctypes.c_int
    library.secp256k1_ecdsa_recover.argtypes = [ctypes.c_void_p] * 4
    library.secp256k1_ecdsa_recover.restype = ctypes.c_int
    library.secp256k1_ec_pubkey_serialize.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                                   ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_uint]
    library.secp256k1_ec_pubkey_serialize.restype = ctypes.c_int
    return library


def sender(digest, parity, r, s):
    require(isinstance(digest, bytes) and len(digest) == 32 and type(parity) is int and parity in (0, 1)
            and type(r) is int and type(s) is int and 0 < r < ORDER and 0 < s <= ORDER // 2,
            'invalid canonical Ethereum signature')
    library = load()
    context = library.secp256k1_context_create(1)
    require(context, 'public signature verification unavailable')
    try:
        signature = (ctypes.c_ubyte * 65)()
        compact = ctypes.create_string_buffer(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))
        message = ctypes.create_string_buffer(digest)
        public = (ctypes.c_ubyte * 64)()
        serialized = (ctypes.c_ubyte * 65)(); length = ctypes.c_size_t(65)
        require(library.secp256k1_ecdsa_recoverable_signature_parse_compact(context, signature, compact, parity) == 1
                and library.secp256k1_ecdsa_recover(context, public, signature, message) == 1
                and library.secp256k1_ec_pubkey_serialize(context, serialized, ctypes.byref(length), public, 2) == 1
                and length.value == 65 and serialized[0] == 4, 'Ethereum signature recovery failed')
        return '0x' + keccak(bytes(serialized)[1:])[-20:].hex()
    finally: library.secp256k1_context_destroy(context)


def self_test():
    """Recover one published Ethereum test transaction; no private key/signing.

    Public factual vector from ethereum/tests c67e485ff8b5be9abc8ad15345ec21aa22e290d9,
    TransactionTests/ttEIP1559/GasLimitPriceProductOverflowtMinusOne.json (MIT).
    Its excessive test fee is deliberately NOT a permitted participation send.
    """
    import rlp
    raw = bytes.fromhex('02f885018084773594009f02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82520894095e7baea6a6c7c4c2dfeb977efac326af552d878080c080a05cbd172231fc0735e0fb994dd5b1a4939170a260b36f0427a8a80866b063b948a07c230f7f578dd61785c93361b9871c0706ebfa6d06e3f4491dc9558c5202ed36')
    decoded = rlp.dynamic_fee(raw)
    require(sender(keccak(decoded['signing_payload']), decoded['parity'], decoded['r'], decoded['s'])
            == '0xae2aec498d20869d441eaaf708fb1e375ae1787d'
            and keccak(raw).hex() == 'dad8bff3ecfcf95169b1d5625b47f3372be795802bc4fe570991cf332f609334',
            'qualified public recovery vector failed against the host cryptographic runtime')
    return True

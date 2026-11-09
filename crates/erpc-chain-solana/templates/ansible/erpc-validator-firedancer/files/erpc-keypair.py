#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# A Solana keypair file without the Solana CLI, for a Firedancer host, which
# has none. `firedancer keys` would do, but it loads the validator's whole
# configuration first and refuses on a host whose cores do not fit its
# default layout.
#
#   erpc-keypair.py new <path>      writes a new keypair (0600, never over a
#                                   file that exists) and prints its public key
#   erpc-keypair.py pubkey <path>   prints the public key of a keypair file
#
# The key is made by openssl; the file is what solana-keygen writes: a JSON
# list of the 32-byte seed and the 32-byte public key.

import json
import os
import subprocess
import sys

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = ALPHABET[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def openssl(args, given=None) -> bytes:
    return subprocess.run(
        ["openssl", *args], input=given, capture_output=True, check=True
    ).stdout


def new(path: str) -> None:
    # PKCS#8 for Ed25519 ends with the 32-byte seed, SPKI with the public key.
    private = openssl(["genpkey", "-algorithm", "ed25519", "-outform", "DER"])
    public = openssl(["pkey", "-inform", "DER", "-pubout", "-outform", "DER"], private)
    seed, key = private[-32:], public[-32:]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(list(seed + key), f)
    print(base58(key))


def pubkey(path: str) -> None:
    with open(path) as f:
        key = json.load(f)
    if len(key) != 64 or not all(isinstance(b, int) and 0 <= b < 256 for b in key):
        sys.exit(f"{path} is not a keypair file")
    print(base58(bytes(key[32:])))


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("new", "pubkey"):
        sys.exit("usage: erpc-keypair.py new|pubkey <path>")
    {"new": new, "pubkey": pubkey}[sys.argv[1]](sys.argv[2])

# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0

# Tests of the collector's plain-text key search, on fixture trees made under
# a temporary directory. Every key, seed phrase and secret is made when the
# test runs. node-security-posture-test.py runs these too.

import ast
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import stat
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
WORD_LIST = (HERE / "bip39-english.txt").read_text()
KEYS = runpy.run_path(str(HERE / "node-security-keys.py"), init_globals={"BIP39_ENGLISH": WORD_LIST})
WORDS = WORD_LIST.split()
BASE58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def hex_key():
    return os.urandom(32).hex()


def phrase(count):
    return " ".join(WORDS[int.from_bytes(os.urandom(2), "big") % 2048] for _ in range(count))


def base58_secret():
    while True:
        number = int.from_bytes(os.urandom(64), "big")
        text = b""
        while number:
            number, digit = divmod(number, 58)
            text = BASE58[digit:digit + 1] + text
        if len(text) in (87, 88):
            return text.decode()


def keypair_json(pair):
    return json.dumps(list(pair))


def array_with(value):
    return "[" + ", ".join([str(value)] + [str(i * 3 % 256) for i in range(1, 64)]) + "]"


def groups(result):
    return [(g["kind"], g["role"], g["location"], g["access"], g["count"]) for g in result["groups"]]


def search(root, entries=None, seconds=20):
    found = KEYS["KeySearch"](str(root), time.monotonic() + seconds, entries or KEYS["KEY_ENTRIES"])
    found.run()
    return found.result()


class Tree:
    """A fixture server under a temporary directory, with an empty /proc."""

    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="erpc-keys-"))
        (self.root / "proc").mkdir()
        self.chmod("", 0o755)

    def write(self, path, contents, mode=0o644):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(contents.encode() if isinstance(contents, str) else contents)
        target.chmod(mode)

    def chmod(self, path, mode):
        (self.root / path).chmod(mode)

    def status(self, pid, uid):
        self.write(f"proc/{pid}/status", f"Name:\tagave-validator\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")

    def validator(self, pid, identity, uid=None, program="agave-validator"):
        self.write(f"proc/{pid}/comm", program + "\n")
        self.write(f"proc/{pid}/cmdline", f"{program}\0--identity\0{identity}\0".encode())
        self.status(pid, os.getuid() if uid is None else uid)

    def remove(self):
        for directory, names, _ in os.walk(self.root):
            for name in names:
                path = os.path.join(directory, name)
                if not os.path.islink(path):
                    os.chmod(path, 0o755)
        shutil.rmtree(self.root)


def key_host():
    """A server with a key of every kind in every place, and what must not be
    counted beside them; with the secrets written there."""
    tree = Tree()
    identity, wallet, hidden, docker, outside = (os.urandom(64) for _ in range(5))
    key = hex_key()
    words = phrase(24)
    typed = base58_secret()
    big = key.encode().ljust(KEYS["FILE_LIMIT"] + 1, b" ")
    for path, contents, mode in [
        ("home/sol/validator-keypair.json", keypair_json(identity), 0o644),
        ("home/sol/wallet/id.json", keypair_json(wallet), 0o600),
        ("home/sol/private/k.json", keypair_json(hidden), 0o644),
        ("home/sol/.config/deployer.key", f"0x{key}\n", 0o600),
        ("var/lib/docker/volumes/v1/_data/id.json", keypair_json(docker), 0o644),
        ("var/lib/app/key.hex", key, 0o644),
        ("tmp/x/wallet.key", key, 0o644),
        ("opt/bot/seed.txt", f"{words}\n", 0o644),
        ("etc/bot/keystore.json", '{"address": "ab", "privateKey": "0x%s"}' % key, 0o640),
        ("srv/app/.env", f'LOG_LEVEL=info\nPRIVATE_KEY=0x{key}\nBOT_MNEMONIC="{words}"\n', 0o644),
        ("root/.bash_history", f"ls\nimport {typed}\nexport WALLET_KEY={key}\n", 0o600),
        ("home/sol/.local/share/fish/fish_history",
         f"- cmd: env PRIVATE_KEY={key} ./bot\n- cmd: cast wallet import --private-key {key}\n", 0o600),
        ("proc/41/environ", f"HOME=/home/sol\0PRIVATE_KEY={key}\0SEED_PHRASE=op://v/i/f\0", 0o644),
        # Not found:
        ("home/sol/ledger/id.json", keypair_json(os.urandom(64)), 0o644),
        ("mnt/keys/real.json", keypair_json(outside), 0o644),
        ("home/sol/notes/UTC--2024", '{"version": 3, "address": "ab", "crypto": {"cipher": "aes-128-ctr"}}', 0o600),
        ("home/sol/app/.env", "PRIVATE_KEY=op://vault/item/key\nMNEMONIC=${MNEMONIC_FILE}\n", 0o644),
        ("home/sol/bad.json", array_with(256), 0o644),
        ("home/sol/short.key", key[1:], 0o644),
        ("home/sol/server.pem", f"{key}\n", 0o644),
        ("var/lib/docker/overlay2/l1/diff/id.json", keypair_json(os.urandom(64)), 0o644),
        ("home/sol/big.key", big, 0o644),
        ("opt/bot/README", "no keys here\n", 0o644),
    ]:
        tree.write(path, contents, mode)
    tree.validator(41, "/home/sol/validator-keypair.json")
    os.symlink("../../mnt/keys/real.json", tree.root / "home/sol/link.json")
    os.symlink("../mnt/keys", tree.root / "opt/keys")
    # A pipe is neither opened nor waited on.
    os.mkfifo(tree.root / "tmp/x/pipe.key")
    for directory, mode in [("home", 0o755), ("home/sol", 0o750), ("home/sol/private", 0o700),
                            ("root", 0o700), ("etc", 0o755), ("etc/bot", 0o755),
                            ("var/lib/docker", 0o710), ("var/lib/docker/volumes", 0o701), ("tmp", 0o1777)]:
        tree.chmod(directory, mode)
    secrets = [key, words, typed]
    for pair in (identity, wallet, hidden, docker, outside):
        secrets += [keypair_json(pair), json.dumps(list(pair[32:]))[1:-1]]
    return tree, secrets


class DetectorTests(unittest.TestCase):
    def kind(self, name, contents):
        hit = KEYS["classify"](name.encode(), contents.encode() if isinstance(contents, str) else contents)
        return hit and hit[0]

    def test_the_word_list_is_the_sorted_english_list(self):
        self.assertEqual(len(WORDS), 2048)
        self.assertEqual(WORDS, sorted(WORDS))
        self.assertTrue(all(3 <= len(w) <= 8 and w.isascii() and w.islower() for w in WORDS))
        self.assertEqual(hashlib.sha256(WORD_LIST.encode()).hexdigest(),
                         "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda")

    def test_solana_keypairs_are_exactly_64_bytes(self):
        pair = os.urandom(64)
        self.assertEqual(KEYS["classify"](b"id.json", keypair_json(pair).encode()),
                         ("solana_keypair", 1, hashlib.sha256(pair).digest()))
        keypair = KEYS["keypair"]
        self.assertIsNotNone(keypair(array_with(255).encode()))
        self.assertIsNotNone(keypair(b" \n" + array_with(7).replace(", ", " ,\t").encode() + b"\r\n"))
        self.assertIsNone(keypair(array_with(256).encode()))
        self.assertIsNone(keypair(array_with(1).replace("1, ", "", 1).encode()))
        self.assertIsNone(keypair(array_with(1).replace("[", "[1, ", 1).encode()))
        self.assertIsNone(keypair(array_with(1).replace("1", "-1", 1).encode()))
        self.assertIsNone(keypair(array_with(1).replace("1", "0001", 1).encode()))
        self.assertIsNone(keypair(array_with(1).replace(", ", ",\x0b", 1).encode()))
        self.assertIsNone(keypair(b"[]"))
        self.assertIsNone(keypair(b"["))

    def test_hex_keys_need_a_key_name_and_64_digits(self):
        key = hex_key()
        self.assertEqual(self.kind("wallet.txt", key), "evm_private_key")
        self.assertEqual(self.kind("deployer.KEY", f"0x{key}\n"), "evm_private_key")
        self.assertEqual(self.kind("private", key), "evm_private_key")
        self.assertIsNone(self.kind("notes.txt", key))
        self.assertIsNone(self.kind("server.pem", key))
        self.assertIsNone(self.kind("server.PEM", key))
        self.assertIsNone(self.kind("wallet.key", key[1:]))
        self.assertIsNone(self.kind("wallet.key", f"{key} {key}"))

    def test_seed_phrases_are_whole_files_of_list_words(self):
        for count in (12, 15, 18, 21, 24):
            self.assertEqual(self.kind("seed.txt", phrase(count)), "mnemonic", count)
        self.assertTrue(KEYS["mnemonic"](phrase(12).replace(" ", "\n").encode()))
        for count in (11, 13, 25):
            self.assertFalse(KEYS["mnemonic"](phrase(count).encode()), count)
        self.assertFalse(KEYS["mnemonic"](phrase(12).upper().encode()))
        words = phrase(12).split()
        words[3] = "erpc"
        self.assertFalse(KEYS["mnemonic"](" ".join(words).encode()))
        # A vertical tab is no whitespace to Rust, nor here.
        self.assertFalse(KEYS["mnemonic"](phrase(12).replace(" ", "\x0b", 1).encode()))

    def test_only_keystores_without_encryption_are_found(self):
        key = hex_key()
        self.assertEqual(self.kind("UTC--wallet", '{"address": "ab", "privateKey": "%s"}' % key),
                         "unencrypted_keystore")
        self.assertEqual(self.kind("k.json", '{"secret_key": "ed25519:%s"}' % key), "unencrypted_keystore")
        self.assertEqual(self.kind("k.json", '{"Private-Key": 1}'), "unencrypted_keystore")
        for crypto in ("crypto", "Crypto"):
            v3 = ('{"version": 3, "id": "x", "address": "ab", "%s": {"ciphertext": "%s", '
                  '"cipher": "aes-128-ctr"}}' % (crypto, key))
            self.assertIsNone(self.kind("UTC--2024", v3))
        master = ('{"format": "erpc-keystore-master", "version": 1, "key_id": "00", "kdf": '
                  '"pbkdf2-hmac-sha256", "iterations": 600000, "salt": "%s", "cipher": '
                  '"chacha20-poly1305", "nonce": "00", "wrapped": "%s"}' % (key, key))
        entry = ('{"format": "erpc-keystore-entry", "version": 1, "key_id": "00", "name": "worker/bot", '
                 '"kind": "key", "kdf": "hkdf-sha256", "salt": "%s", "cipher": "chacha20-poly1305", '
                 '"nonce": "00", "sealed": "%s"}' % (key, key))
        self.assertIsNone(self.kind("master.json", master))
        self.assertIsNone(self.kind("bot.json", entry))
        self.assertIsNone(self.kind("x.json", "{not json"))
        self.assertIsNone(self.kind("x.json", '["privateKey"]'))
        self.assertIsNone(self.kind("x.json", '{"privateKey": NaN}'))
        # Only the top level's fields count; a nested key field does not.
        self.assertIsNone(self.kind("x.json", '{"wallet": {"privateKey": "%s"}}' % key))
        self.assertIsNone(self.kind("x.json", "[" * 100000))
        # Nested deeper than the parser goes.
        self.assertIsNone(self.kind("x.json", '{"privateKey": 1, "a": ' * 20000))
        self.assertIsNone(self.kind("x.json", '{"privateKey": 1, "a": ' * 20000 + "1" + "}" * 20000))

    def test_env_files_count_secrets_written_out(self):
        key = hex_key()
        words = phrase(12)
        lines = (
            f"# PRIVATE_KEY={key}\nexport PRIVATE_KEY={key}\nBOT_MNEMONIC=\"{words}\"\nSOLANA_KEYPAIR='{key}'\n"
            "SECRET_KEY=op://vault/item/field\nWALLET_KEY=${WALLET_KEY_FILE}\nSEED_PHRASE=keychain:seed\n"
            "KEYPAIR_PATH=keystore:bot\nEMPTY_PRIVATE_KEY=\nQUOTED_PRIVATE_KEY=\"\"\nLOG_LEVEL=info\n"
            "SOLANA_KEYPAIR=~/.config/solana/id.json\nVALIDATOR_KEYPAIR=/home/sol/id.json\n"
            f"PRIVATE_KEY=./deployer.key\nKEYPAIR_FILE=id.json\nwallet_key_dir={key}\n"
        )
        for name in (".env", "bot.env", "environment"):
            self.assertEqual(KEYS["classify"](name.encode(), lines.encode()), ("env_secret", 3, None), name)
        self.assertIsNone(self.kind(".env.example", lines))
        self.assertIsNone(self.kind(".env", "LOG_LEVEL=info\n"))
        self.assertEqual(KEYS["env_lines"](f"export  PRIVATE_KEY = '{key}' \n".encode()), 1)

    def test_process_environments_count_secrets_written_out(self):
        key = hex_key()
        environ = (f"PATH=/usr/bin\0PRIVATE_KEY={key}\0SEED_PHRASE=op://v/i/f\0HOME=/root\0"
                   "KEYPAIR=/run/keys/id.json\0")
        self.assertEqual(KEYS["environ_secrets"](environ.encode()), 1)
        self.assertEqual(KEYS["environ_secrets"](b"PATH=/usr/bin\0WALLET_KEY=\0=x\0"), 0)

    def test_history_lines_with_keys_are_counted(self):
        key = hex_key()
        history = (
            f"ls -la\ncast send --private-key 0x{key} 0xab\nimport-key {base58_secret()}\n"
            "export PRIVATE_KEY=abc\nexport PRIVATE_KEY=\"$(op read op://v/i/f)\"\n"
            f"echo {key[1:]}\nunset PRIVATE_KEY\n: 1700000000:0;WALLET_KEY=xyz ./bot\n"
            "export SOLANA_KEYPAIR=~/.config/solana/id.json\nKEYPAIR_PATH=id.json ./bot\n"
        )
        lines = KEYS["history_lines"]
        self.assertEqual(lines(history.encode()), 4)
        self.assertEqual(lines(b"git log --oneline\n"), 0)
        self.assertEqual(lines(b"a=b PRIVATE_KEY=x=y\n"), 1)
        self.assertEqual(lines(f"x{key}y\n{key}0\n".encode()), 1)

    def test_a_line_built_to_be_slow_is_checked_in_time_with_its_length(self):
        # Each of these would take time growing with the square of its length
        # in a check that is not linear.
        mib = 1024 * 1024
        lines = [b"=" * mib, b"PRIVATE_KEY=$" * (mib // 13), b"a=" * (mib // 2),
                 b"A" * mib + b"=x", b"a" * mib, b"1" * mib, b"PRIVATE_KEY" * (mib // 11)]
        started = time.monotonic()
        found = []
        for line in lines:
            found.append(KEYS["history_lines"](line))
            self.assertEqual(KEYS["environ_secrets"](line), 0)
            self.assertIsNone(KEYS["classify"](b".env", line))
            self.assertIsNone(KEYS["classify"](b"wallet.key", line))
        self.assertEqual(found, [0, 0, 0, 0, 0, 0, 0])
        self.assertLess(time.monotonic() - started, 10)

    def test_places_are_encoded_so_that_json_leaves_them_as_they_are(self):
        place = KEYS["place"]
        self.assertEqual(place(b"/home/sol/id.json"), "/home/sol/id.json")
        self.assertEqual(place(b'/a%b"c\\d\xff\x1b\n \xe3\x81\x82'), "/a%25b%22c%5Cd%FF%1B%0A %E3%81%82")
        every = bytes(range(1, 256))
        encoded = place(every)
        self.assertEqual(json.dumps(encoded), '"' + encoded + '"')
        self.assertTrue(encoded.isascii())


class WalkTests(unittest.TestCase):
    def test_keys_are_counted_by_kind_role_place_and_access(self):
        tree, _ = key_host()
        self.addCleanup(tree.remove)
        result = search(tree.root)
        self.assertEqual(groups(result), [
            ("solana_keypair", "validator_identity", "home", "group", 1),
            ("solana_keypair", "unknown", "home", "owner_only", 2),
            ("solana_keypair", "unknown", "docker", "owner_only", 1),
            ("evm_private_key", "unknown", "home", "owner_only", 1),
            ("evm_private_key", "unknown", "var", "world", 1),
            ("evm_private_key", "unknown", "tmp", "world", 1),
            ("mnemonic", "unknown", "opt", "world", 1),
            ("unencrypted_keystore", "unknown", "etc", "group", 1),
            ("env_secret", "unknown", "srv", "world", 2),
            ("process_env_secret", "unknown", "process_env", "owner_only", 1),
            ("history_secret", "unknown", "shell_history", "owner_only", 4),
        ])
        self.assertEqual(result["coverage"], "complete")
        shown = [sorted(group["places"]) for group in result["groups"]]
        self.assertEqual(shown[0], ["/home/sol/validator-keypair.json"])
        self.assertEqual(shown[1], ["/home/sol/private/k.json", "/home/sol/wallet/id.json"])
        self.assertEqual(shown[2], ["/var/lib/docker/volumes/v1/_data/id.json"])
        self.assertEqual(shown[9], ["/proc/41/environ"])
        self.assertEqual(shown[10], ["/home/sol/.local/share/fish/fish_history", "/root/.bash_history"])
        self.assertTrue(all(group["more"] == 0 for group in result["groups"]))
        self.assertNotIn(str(tree.root), json.dumps(result))

    def test_the_result_holds_no_secret(self):
        tree, secrets = key_host()
        self.addCleanup(tree.remove)
        text = json.dumps(search(tree.root))
        for secret in secrets:
            self.assertNotIn(secret, text)
        self.assertNotIn(" ".join(secrets[1].split()[:2]), text)

    def test_without_the_identity_its_keypair_is_a_wallet_key(self):
        tree, _ = key_host()
        self.addCleanup(tree.remove)
        shutil.rmtree(tree.root / "proc/41")
        result = search(tree.root)
        self.assertIn(("solana_keypair", "unknown", "home", "group", 1), groups(result))
        self.assertTrue(all(group["role"] == "unknown" for group in result["groups"]))
        self.assertEqual(result["coverage"], "complete")

    def test_a_spent_budget_or_an_unread_process_makes_the_search_partial(self):
        tree, _ = key_host()
        self.addCleanup(tree.remove)
        self.assertEqual(search(tree.root, entries=5)["coverage"], "partial")
        # Spent before anything was read, the search has nothing to say.
        self.assertEqual(search(tree.root, seconds=-1), {"coverage": "unreadable", "groups": []})
        # A process whose environment cannot be read.
        (tree.root / "proc/42/environ").mkdir(parents=True)
        self.assertEqual(search(tree.root)["coverage"], "partial")
        shutil.rmtree(tree.root / "proc/42")
        self.assertEqual(search(tree.root)["coverage"], "complete")
        # Processes that cannot be listed.
        shutil.rmtree(tree.root / "proc")
        self.assertEqual(search(tree.root)["coverage"], "partial")

    def test_a_start_that_is_a_link_is_not_followed_and_says_so(self):
        tree = Tree()
        self.addCleanup(tree.remove)
        tree.write("elsewhere/id.json", keypair_json(os.urandom(64)))
        tree.write("etc/hostname", "node\n")
        os.symlink("elsewhere", tree.root / "home")
        result = search(tree.root)
        self.assertEqual(result, {"coverage": "partial", "groups": []})
        os.unlink(tree.root / "home")
        # So does a link on the way to a start.
        tree.write("real/docker/volumes/v/id.json", keypair_json(os.urandom(64)))
        (tree.root / "var/lib").mkdir(parents=True)
        os.symlink("../../real/docker", tree.root / "var/lib/docker")
        result = search(tree.root)
        self.assertEqual(result, {"coverage": "partial", "groups": []})
        # And a file in place of a directory on the way to one; a start that
        # is itself a file is no start.
        os.unlink(tree.root / "var/lib/docker")
        tree.write("var/lib/docker", "not a directory\n")
        self.assertEqual(search(tree.root)["coverage"], "partial")
        os.unlink(tree.root / "var/lib/docker")
        tree.write("var/tmp", "not a directory\n")
        self.assertEqual(search(tree.root)["coverage"], "complete")

    def test_nothing_to_read_is_unreadable_and_nothing_found_is_complete(self):
        tree = Tree()
        self.addCleanup(tree.remove)
        self.assertEqual(search(tree.root), {"coverage": "unreadable", "groups": []})
        tree.write("etc/hostname", "node\n")
        self.assertEqual(search(tree.root), {"coverage": "complete", "groups": []})

    def test_access_is_the_narrowest_the_modes_and_groups_allow(self):
        access = KEYS["access_of"]
        # Group 0 is root's, 50 a staff group, 1000 a person's.
        root = [(0, 0o755)]
        self.assertEqual(access(root, 0, 0o644), "world")
        self.assertEqual(access(root, 0, 0o640), "group")
        self.assertEqual(access(root, 0, 0o600), "owner_only")
        home = root + [(1000, 0o750)]
        self.assertEqual(access(home, 1000, 0o644), "group")
        self.assertEqual(access(home, 1000, 0o604), "owner_only")
        # The group of another directory passes it as others do.
        self.assertEqual(access(home, 50, 0o640), "owner_only")
        self.assertEqual(access(root + [(1000, 0o751)], 50, 0o640), "group")
        self.assertEqual(access(root + [(1000, 0o700)], 1000, 0o666), "owner_only")
        # Docker's 0710 and 0701 directories let no group but root's pass.
        self.assertEqual(access(root + [(0, 0o710), (0, 0o701)], 0, 0o644), "owner_only")
        self.assertEqual(access(root + [(0, 0o710)], 0, 0o640), "group")

    def test_the_walk_stays_on_its_filesystem_except_into_homes(self):
        descend = KEYS["descend"]
        self.assertEqual(descend(False, 0, 1, 1), 1)
        self.assertIsNone(descend(False, 0, 1, 2))
        self.assertIsNone(descend(False, 3, 1, 2))
        # /home/<name> may be mounted on its own; below it, the walk stays.
        self.assertEqual(descend(True, 0, 1, 2), 2)
        self.assertIsNone(descend(True, 1, 2, 3))

    def test_another_filesystem_is_never_opened_to_read(self):
        tree = Tree()
        self.addCleanup(tree.remove)
        tree.write("opt/mounted/wallet.key", hex_key())
        opened = []
        reopen = KEYS["reopen"]

        def recording(fd, directory):
            opened.append((stat.S_IFMT(os.fstat(fd).st_mode), directory))
            return reopen(fd, directory)

        globals_ = KEYS["KeySearch"].walk.__globals__
        with patch.dict(globals_, reopen=recording, descend=lambda *_: None):
            result = search(tree.root)
        # Only /opt itself was opened: the directory below it, held but on
        # "another filesystem", was not.
        self.assertEqual(opened, [(stat.S_IFDIR, True)])
        self.assertEqual(result, {"coverage": "complete", "groups": []})

    def test_counts_are_capped_and_places_bounded(self):
        search_ = KEYS["KeySearch"]("/", time.monotonic() + 20)
        search_.opened = 1
        key = ("history_secret", "unknown", "shell_history", "world")
        search_.add(key, KEYS["MAX_COUNT"] + 1, b"/a")
        result = search_.result()
        self.assertEqual(result["groups"][0]["count"], KEYS["MAX_COUNT"])
        self.assertEqual(result["coverage"], "partial")

        search_ = KEYS["KeySearch"]("/", time.monotonic() + 20)
        search_.opened = 1
        for n in range(12):
            search_.add(("mnemonic", "unknown", "opt", "world"), 1, b"/k/%d" % n)
        group = search_.result()["groups"][0]
        self.assertEqual((len(group["places"]), group["more"], group["count"]), (10, 2, 12))
        self.assertEqual(search_.result()["coverage"], "complete")

    def test_places_keep_to_their_budget_whatever_the_bytes(self):
        """All 148 groups, each with more keys and places than shown, at
        paths that encode at three characters a byte."""
        search_ = KEYS["KeySearch"]("/", time.monotonic() + 20)
        search_.opened = 1
        files = ("home", "root_home", "etc", "opt", "srv", "var", "tmp", "docker")
        keys = []
        for kind in KEYS["KINDS"]:
            roles = KEYS["ROLES"] if kind == "solana_keypair" else ("unknown",)
            locations = {"process_env_secret": ("process_env",), "history_secret": ("shell_history",)}.get(kind, files)
            access = ("owner_only",) if kind == "process_env_secret" else KEYS["ACCESS"]
            keys += [(kind, r, l, a) for r in roles for l in locations for a in access]
        self.assertEqual(len(keys), 148)
        for n, key in enumerate(keys):
            for m in range(12):
                search_.add(key, KEYS["MAX_COUNT"], b"/" + bytes([0x80 + n % 100]) * (300 + m))
            search_.add(key, 1, b"/\xff" * 2000)
        result = search_.result()
        places = [place for group in result["groups"] for place in group["places"]]
        self.assertTrue(all(len(place) <= KEYS["PLACE_LIMIT"] for place in places))
        self.assertLessEqual(sum(len(place) + 3 for place in places), KEYS["PLACES_BUDGET"])
        self.assertGreater(len(places), 0)
        for group in result["groups"]:
            self.assertEqual(group["count"], KEYS["MAX_COUNT"])
            self.assertLessEqual(len(group["places"]) + group["more"], group["count"])
        self.assertEqual(result["coverage"], "partial")
        text = json.dumps(result, separators=(",", ":"))
        self.assertTrue(text.isascii())
        self.assertLessEqual(len(text), 28 * 1024)

    def test_an_identity_given_through_a_link_elsewhere_is_still_the_identity(self):
        tree = Tree()
        self.addCleanup(tree.remove)
        identity = os.urandom(64)
        # The validator was given a link to a key outside every start, as a
        # setup that switches identities does.
        tree.write("mnt/ramdisk/staked.json", keypair_json(identity), 0o600)
        tree.write("home/sol/backup/staked.json", keypair_json(identity), 0o600)
        os.symlink("../../mnt/ramdisk/staked.json", tree.root / "home/sol/identity.json")
        tree.chmod("home/sol", 0o750)
        tree.validator(7, "/home/sol/identity.json")
        result = search(tree.root)
        self.assertEqual(groups(result), [("solana_keypair", "validator_identity", "home", "owner_only", 1)])
        # The walk itself followed no link: only the copy it reached counts.
        self.assertEqual(result["groups"][0]["places"], ["/home/sol/backup/staked.json"])
        self.assertEqual(result["coverage"], "complete")

    def test_a_keypair_is_the_identity_only_when_all_64_bytes_are(self):
        tree = Tree()
        self.addCleanup(tree.remove)
        identity = os.urandom(64)
        forged = os.urandom(32) + identity[32:]
        tree.write("home/sol/id.json", keypair_json(identity), 0o600)
        tree.write("tmp/public-half.json", keypair_json(forged), 0o644)
        tree.validator(8, "/home/sol/id.json")
        self.assertEqual(groups(search(tree.root)), [
            ("solana_keypair", "validator_identity", "home", "owner_only", 1),
            ("solana_keypair", "unknown", "tmp", "world", 1),
        ])

    def test_unreadable_identities_directories_and_files_make_the_search_partial(self):
        if os.geteuid() == 0:
            self.skipTest("the superuser reads through modes")
        tree = Tree()
        self.addCleanup(tree.remove)
        tree.write("etc/hostname", "node\n")
        self.assertEqual(search(tree.root)["coverage"], "complete")
        tree.write("mnt/id.json", keypair_json(os.urandom(64)), 0o000)
        tree.validator(9, "/mnt/id.json")
        self.assertEqual(search(tree.root)["coverage"], "partial", "the identity")
        shutil.rmtree(tree.root / "proc/9")
        tree.write("etc/secret.key", hex_key(), 0o000)
        self.assertEqual(search(tree.root)["coverage"], "partial", "the file")
        tree.chmod("etc/secret.key", 0o644)
        self.assertEqual(search(tree.root)["coverage"], "complete")
        (tree.root / "etc/private").mkdir()
        tree.chmod("etc/private", 0o000)
        self.assertEqual(search(tree.root)["coverage"], "partial", "the directory")
        tree.chmod("etc/private", 0o755)
        tree.chmod("etc", 0o000)
        # No start could be read at all.
        self.assertEqual(search(tree.root)["coverage"], "unreadable")
        tree.write("opt/README", "no keys here\n")
        self.assertEqual(search(tree.root)["coverage"], "partial", "a start")
        tree.chmod("etc", 0o755)

    def test_a_tree_deeper_than_the_walk_goes_is_partial(self):
        tree = Tree()
        self.addCleanup(tree.remove)
        deepest = tree.root / "opt" / "/".join(["d"] * (KEYS["MAX_DEPTH"] + 1))
        deepest.mkdir(parents=True)
        self.assertEqual(search(tree.root)["coverage"], "partial")
        deepest.rmdir()
        self.assertEqual(search(tree.root)["coverage"], "complete")

    def test_only_directories_and_regular_files_are_opened_to_read(self):
        hold = KEYS["hold"]
        # A device, even when a link leads to it, is held, never opened.
        fd, status = hold(b"/dev/null", follow=True)
        os.close(fd)
        self.assertTrue(stat.S_ISCHR(status.st_mode))
        tree = Tree()
        self.addCleanup(tree.remove)
        tree.write("tmp/real.key", "x")
        os.symlink("/dev/null", tree.root / "tmp/null.key")
        os.symlink("real.key", tree.root / "tmp/link.key")
        os.mkfifo(tree.root / "tmp/pipe.key")
        directory = os.open(tree.root / "tmp", os.O_PATH | os.O_CLOEXEC)
        self.addCleanup(os.close, directory)
        fd, status = hold(b"link.key", directory)
        os.close(fd)
        self.assertTrue(stat.S_ISLNK(status.st_mode))
        opened = []
        reopen = KEYS["reopen"]

        def recording(fd, directory):
            opened.append(stat.S_IFMT(os.fstat(fd).st_mode))
            return reopen(fd, directory)

        held = []

        def holding(name, dir_fd=None, follow=False):
            held.append(name)
            return hold(name, dir_fd, follow)

        with patch.dict(KEYS["KeySearch"].walk.__globals__, reopen=recording, hold=holding):
            self.assertEqual(search(tree.root), {"coverage": "complete", "groups": []})
        self.assertEqual(sorted(opened), sorted([stat.S_IFDIR, stat.S_IFREG]))
        # Links and the pipe were known from their listing and not even held.
        self.assertEqual([name for name in held if name.endswith(b".key")], [b"real.key"])

    def test_an_identity_is_read_only_if_the_validators_user_owns_it_and_it_is_small(self):
        tree = Tree()
        self.addCleanup(tree.remove)
        tree.write("home/sol/id.json", keypair_json(os.urandom(64)), 0o600)
        tree.write("home/sol/empty.json", "", 0o600)

        def role(pid, uid, path="/home/sol/id.json"):
            shutil.rmtree(tree.root / "proc", ignore_errors=True)
            (tree.root / "proc").mkdir()
            if uid is not None:
                tree.validator(pid, path, uid)
            result = search(tree.root)
            return [group["role"] for group in result["groups"]], result["coverage"]

        # The validator's own user, and root, may name it.
        self.assertEqual(role(10, os.getuid()), (["validator_identity"], "complete"))
        self.assertEqual(role(11, 0), (["validator_identity"], "complete"))
        # A program of another user cannot make this read the file.
        self.assertEqual(role(12, os.getuid() + 1), (["unknown"], "partial"))
        # Nor is an empty file read, as a kernel file that never ends would
        # look.
        self.assertEqual(role(13, os.getuid(), "/home/sol/empty.json")[1], "partial")
        # A process without a status says nothing.
        role(14, os.getuid())
        os.unlink(tree.root / "proc/14/status")
        self.assertEqual(search(tree.root)["coverage"], "partial")
        # A process that ended is no loss.
        self.assertEqual(role(15, None), (["unknown"], "complete"))

    def test_kernel_filesystems_are_told_apart(self):
        hold = KEYS["hold"]
        fd, _ = hold(b"/proc/self/status", follow=True)
        self.addCleanup(os.close, fd)
        self.assertTrue(KEYS["kernel_file"](fd))
        tree = Tree()
        self.addCleanup(tree.remove)
        tree.write("etc/hostname", "node\n")
        fd, _ = hold(os.fsencode(tree.root / "etc/hostname"))
        self.addCleanup(os.close, fd)
        self.assertFalse(KEYS["kernel_file"](fd))
        # A root validator named a non-empty kernel file: it is not read, and
        # the search says it could not tell.
        for candidate in ("/sys/kernel/mm/transparent_hugepage/enabled", "/sys/devices/system/cpu/online",
                          "/sys/kernel/profiling"):
            if os.path.isfile(candidate) and 0 < os.stat(candidate).st_size <= KEYS["FILE_LIMIT"]:
                break
        else:
            self.skipTest("no sysfs file to name")
        search_ = KEYS["KeySearch"](str(tree.root), time.monotonic() + 20)
        tree.status(16, 0)

        def refuse(fd, directory):
            raise AssertionError("a kernel file was opened to read")

        with patch.dict(KEYS["KeySearch"].walk.__globals__, reopen=refuse):
            search_.read_identity(os.fsencode(tree.root / "proc/16"), candidate.encode())
        self.assertTrue(search_.partial)

    def test_a_validator_whose_identity_is_unknown_makes_the_search_partial(self):
        tree = Tree()
        self.addCleanup(tree.remove)
        tree.write("etc/hostname", "node\n")
        tree.write("proc/20/comm", "fdctl\n")
        self.assertEqual(search(tree.root)["coverage"], "partial", "Firedancer")
        shutil.rmtree(tree.root / "proc/20")
        tree.write("proc/21/comm", "solana-validato\n")
        tree.write("proc/21/cmdline", b"solana-validator\0--ledger\0/mnt/ledger\0")
        self.assertEqual(search(tree.root)["coverage"], "partial", "no --identity")
        tree.write("proc/21/cmdline", b"solana-validator\0--identity=id.json\0")
        self.assertEqual(search(tree.root)["coverage"], "partial", "no working directory")
        tree.write("home/sol/id.json", keypair_json(os.urandom(64)), 0o600)
        tree.status(21, os.getuid())
        os.symlink("/home/sol", tree.root / "proc/21/cwd")
        result = search(tree.root)
        self.assertEqual(result["coverage"], "complete")
        self.assertEqual(result["groups"][0]["role"], "validator_identity")

    def test_identity_arguments_are_read_as_the_validator_reads_them(self):
        argument = KEYS["identity_argument"]
        self.assertEqual(argument(b"agave-validator\0--identity\0/a\0"), b"/a")
        self.assertEqual(argument(b"agave-validator\0-i\0/a\0--identity=/b\0"), b"/b")
        self.assertEqual(argument(b"agave-validator\0--identity=/a\0--identity\0"), None)
        self.assertEqual(argument(b"agave-validator\0--rpc-port\0--identity\0"), None)
        self.assertEqual(argument(b"agave-validator\0-i=/a\0"), None)
        self.assertEqual(argument(b"--identity\0"), None)

    def test_an_environment_too_large_to_read_makes_the_search_partial(self):
        tree = Tree()
        self.addCleanup(tree.remove)
        tree.write("etc/hostname", "node\n")
        environ = f"PRIVATE_KEY={hex_key()}\0".encode().ljust(KEYS["TAIL_LIMIT"] + 1, b"x")
        tree.write("proc/43/environ", environ)
        self.assertEqual(search(tree.root), {"coverage": "partial", "groups": []})

    def test_only_the_end_of_a_long_history_is_read_from_a_whole_line(self):
        tree = Tree()
        self.addCleanup(tree.remove)
        tree.chmod("", 0o755)
        early = "export PRIVATE_KEY=abc\n"
        # The tail starts inside this line, after its first 50 bytes.
        cut = "z" * 100 + hex_key() + "\n"
        last = "export WALLET_KEY=xyz\n"
        filler = KEYS["TAIL_LIMIT"] + 50 - len(cut) - len(last)
        history = early + cut + "l" * (filler - 1) + "\n" + last
        self.assertEqual(len(history) - KEYS["TAIL_LIMIT"], len(early) + 50)
        tree.write("root/.bash_history", history, 0o600)
        self.assertEqual(groups(search(tree.root)), [("history_secret", "unknown", "shell_history", "owner_only", 1)])


class IsolationTests(unittest.TestCase):
    """The search runs in a child process: whatever happens there costs only
    its own section, and nothing it prints reaches the report."""

    def run_child(self, search_class=None, root="/nonexistent", seconds=20):
        globals_ = KEYS["start_key_search"].__globals__
        replace = {"KeySearch": search_class} if search_class else {}
        with patch.dict(globals_, replace):
            pending = KEYS["start_key_search"](str(root), seconds)
        return KEYS["finish_key_search"](pending)

    def test_the_child_reports_what_the_search_found(self):
        tree, _ = key_host()
        self.addCleanup(tree.remove)
        self.assertEqual(self.run_child(root=tree.root), search(tree.root))

    def test_an_error_in_the_search_leaves_its_section_partial_or_unreadable(self):
        class Failing(KEYS["KeySearch"]):
            def run(self):
                self.opened = 1
                self.add(("mnemonic", "unknown", "opt", "world"), 1, b"/opt/seed.txt")
                raise RuntimeError("fixture")

        class Empty(KEYS["KeySearch"]):
            def run(self):
                raise MemoryError()

        self.assertEqual(self.run_child(Failing), {"coverage": "partial", "groups": [
            {"kind": "mnemonic", "role": "unknown", "location": "opt", "access": "world",
             "count": 1, "places": ["/opt/seed.txt"], "more": 0}]})
        self.assertEqual(self.run_child(Empty), {"coverage": "unreadable", "groups": []})

    def test_a_stalled_search_reports_what_it_found_as_partial(self):
        class Stalled(KEYS["KeySearch"]):
            def run(self):
                self.opened = 1
                self.add(("mnemonic", "unknown", "opt", "world"), 1, b"/opt/seed.txt")
                time.sleep(120)

        started = time.monotonic()
        result = self.run_child(Stalled, seconds=1)
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(result["coverage"], "partial")
        self.assertEqual(result["groups"][0]["places"], ["/opt/seed.txt"])

    def test_nothing_the_child_prints_reaches_the_collectors_output(self):
        class Noisy(KEYS["KeySearch"]):
            def run(self):
                print("fixture output")
                os.write(1, b"fixture stdout\n")
                os.write(2, b"fixture stderr\n")
                raise RuntimeError("fixture traceback")

        with tempfile.TemporaryFile() as sink:
            saved = [os.dup(1), os.dup(2)]
            try:
                os.dup2(sink.fileno(), 1)
                os.dup2(sink.fileno(), 2)
                result = self.run_child(Noisy)
            finally:
                os.dup2(saved[0], 1)
                os.dup2(saved[1], 2)
                for fd in saved:
                    os.close(fd)
            sink.seek(0)
            self.assertEqual(sink.read(), b"")
        self.assertEqual(result, {"coverage": "unreadable", "groups": []})

    def test_a_child_that_dies_or_says_nothing_leaves_the_keys_unreadable(self):
        class Dying(KEYS["KeySearch"]):
            def run(self):
                os._exit(3)

        self.assertEqual(self.run_child(Dying), {"coverage": "unreadable", "groups": []})
        for reply in (b"not json\n", b'{"coverage":"maybe","groups":[]}\n', b"[]\n", b""):
            read_end, write_end = os.pipe()
            os.write(write_end, reply)
            os.close(write_end)
            pid = os.fork()
            if pid == 0:
                os._exit(0)
            pending = (pid, read_end, time.monotonic())
            self.assertEqual(KEYS["finish_key_search"](pending), {"coverage": "unreadable", "groups": []})


class EntryPointTests(unittest.TestCase):
    """The collector's entry point keeps the rest of the report whatever the
    key search does. The posture reads are replaced, and the search is
    pointed at a fixture tree: nothing here reads this machine."""

    REST = {"listeners": "no_listener", "nftables": "not_observed"}
    UPDATES = {"status": "unknown", "packages": None}

    def collect(self, **parts):
        collect = runpy.run_path(str(HERE / "node-security-posture.py"))["collect"]
        replace = {"report_linux": lambda: dict(self.REST), "security_update_summary": lambda: self.UPDATES}
        replace.update(parts)
        with patch.dict(collect.__globals__, replace):
            report = collect()
        self.assertEqual({k: v for k, v in report.items() if k != "keys"}, dict(self.REST, updates=self.UPDATES))
        return report

    def test_the_key_section_joins_the_report(self):
        tree, _ = key_host()
        self.addCleanup(tree.remove)
        report = self.collect(start_key_search=lambda: KEYS["start_key_search"](str(tree.root)),
                              finish_key_search=KEYS["finish_key_search"])
        self.assertEqual(report["keys"], search(tree.root))

    def test_a_key_search_that_cannot_start_or_finish_leaves_only_its_section_unreadable(self):
        def refuse(*_):
            raise OSError(11, "fixture: no fork")

        unreadable = {"coverage": "unreadable", "groups": []}
        report = self.collect(start_key_search=refuse, finish_key_search=KEYS["finish_key_search"])
        self.assertEqual(report["keys"], unreadable)
        report = self.collect(start_key_search=lambda: "pending", finish_key_search=refuse)
        self.assertEqual(report["keys"], unreadable)

    def test_a_failing_search_leaves_only_its_section_partial(self):
        class Failing(KEYS["KeySearch"]):
            def run(self):
                self.opened = 1
                raise RuntimeError("fixture")

        with patch.dict(KEYS["start_key_search"].__globals__, KeySearch=Failing):
            report = self.collect(start_key_search=lambda: KEYS["start_key_search"]("/nonexistent"),
                                  finish_key_search=KEYS["finish_key_search"])
        self.assertEqual(report["keys"], {"coverage": "partial", "groups": []})

    def test_without_the_key_search_there_is_no_key_section(self):
        self.assertNotIn("keys", self.collect())


class SourceTests(unittest.TestCase):
    def test_the_collector_is_python_3_8(self):
        for name in ("node-security-keys.py", "node-security-posture.py", "node-security-updates.py"):
            ast.parse((HERE / name).read_text(), filename=name, feature_version=(3, 8))
        source = (HERE / "node-security-keys.py").read_text()
        for newer in ("removeprefix", "removesuffix", "strict=", "match ", "| None", ":=", "functools.cache"):
            self.assertNotIn(newer, source)


if __name__ == "__main__":
    unittest.main()

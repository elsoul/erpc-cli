<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

# How `erpc storage` encrypts files

`erpc storage put` encrypts a file on this machine before any of it is sent, unless
`--no-encrypt` is given. ERPC stores only the encrypted bytes and never holds the key. `erpc storage
get` notices an encrypted file by its first bytes and decrypts it.

## The key

- One key per account: 32 random bytes, made by the first `put` that needs one.
- It is kept in the store `erpc login` chose:
  - **1Password**: an item tagged `erpc-storage-key`, titled "ERPC storage encryption key", in the
    login vault, and looked for in that vault only. Every machine signed in to the same vault
    uses the same key.
  - **The macOS keychain**: a generic password, service `erpc-storage-key`.
  - **The file store**: `~/.erpc/storage-key`, mode 0600.
- The Linux keyring erpc uses is the kernel's, which is lost on reboot, so erpc does not keep the
  key there. Sign in with `--store 1password` or `--store file`, or use `--no-encrypt`.
- **Losing the key loses every file encrypted with it.** ERPC cannot recover it.
  - `erpc storage key export --show` prints the key so a copy can be kept away from the machine.
  - `erpc storage key import` takes it back on another machine.
  - `erpc storage key show` prints only the key's id: the first 8 bytes of SHA-256 of the key, in
    hex.

## The format (version 1)

```text
magic    8 bytes   "ERPCENC1"
key id   8 bytes   the first 8 bytes of SHA-256(key)
salt    32 bytes   random, new for every file
payload            the file in 64 KiB chunks, each sealed with ChaCha20-Poly1305
```

**The file key** is HKDF-SHA256 with:
- input key material: the account key;
- salt: the salt from the header;
- info: `erpc storage v1 payload key`.

**Sealing the chunks:**
- Chunk `n` (counting from 0) is sealed under a 12-byte nonce: `n` as 11 bytes big-endian, then
  one byte that is 1 for the last chunk and 0 for the others.
- The 48-byte header is the associated data of every chunk.
- Each sealed chunk is its ciphertext followed by its 16-byte tag.
- Every chunk except the last holds exactly 64 KiB of the file. The last holds the rest, and is
  empty only when the whole file is.
- An encrypted file is therefore `48 + size + 16 × max(1, ⌈size / 65536⌉)` bytes.

**What it protects against:**
- A changed byte (header or payload), a chunk moved, or a file cut short at a chunk boundary all
  fail to decrypt.
- A file encrypted under another key is reported as such, from its key id, before anything is
  decrypted.
- A file that does not start with the header is refused by `erpc storage get`: it was uploaded
  with `--no-encrypt`, or something else was put in place of an encrypted file. `--plain`
  downloads it as it is.

**What it does not protect against:** the header does not name the path a file is stored under.
Two files encrypted with the same key can be swapped by someone who can write to the storage,
and each still decrypts, under the other's name.

This is the payload construction of [age](https://github.com/C2SP/C2SP/blob/main/age.md), with the
account key in place of age's recipients. The cryptography is aws-lc-rs.

## What is not encrypted

- The path a file is stored under, and its size, are visible to ERPC.
- `--no-encrypt` uploads the file as it is.
- Backups made with `erpc backup` are encrypted by restic with its own repository password.

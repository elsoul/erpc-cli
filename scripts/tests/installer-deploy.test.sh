#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Two checks on the installer worker's deploy (installer-worker.yml), whose
# `deploy` job holds the Cloudflare token.
#
# 1. The workflow is pinned by SHA-256, with line endings read as LF so a
#    Windows checkout hashes the same. It is meant to run no package install
#    script in `deploy`, to upload a bundle built by a job that holds no
#    secrets, and to run wrangler with an explicit --config and --env-file.
#    Earlier versions of this test tried to check that from the workflow's
#    text and kept missing valid spellings: npm aliases, options before the
#    subcommand, line continuations, `toJson(secrets)`, quoted or escaped
#    YAML keys, and workflow-wide settings placed after the jobs. So this
#    check does not judge the file. Any edit to it fails here until PINNED
#    is updated in the same pull request, and whoever updates it confirms
#    the checklist printed on failure.
#
# 2. No tracked file is one that wrangler or npm, run in installer/ as the
#    workflow runs them, would read without being named:
#      - anything under installer/dist/. It holds only build output, and the
#        deploy downloads the bundle there. Without --config, wrangler looks
#        for wrangler.json in the script's directory (installer/dist for the
#        deploy, installer/ for the bundle) and every directory above it up
#        to /, then for wrangler.jsonc the same way, then wrangler.toml, and
#        follows a .wrangler/deploy/config.json redirect found on the way
#        up. A wrangler.toml in installer/dist would come before
#        installer/wrangler.toml;
#      - at the repository root or in installer/: wrangler.json,
#        wrangler.jsonc, or anything under .wrangler/. A JSON config there
#        would beat installer/wrangler.toml. (A root wrangler.toml never
#        would, so it is allowed.) Configs above the repository, outside
#        the checkout, are not files this check can see; only the
#        workflow's --config covers them;
#      - in installer/: .env and .env.* (wrangler loads .env and .env.local
#        into its environment, keeping variables already set to a
#        non-empty value), .dev.vars and .dev.vars.* (read by
#        `wrangler dev`, not by deploy), and .npmrc.
#    The workflow's explicit --config and --env-file already stop wrangler
#    reading its config and .env files from these places during a deploy;
#    npm still reads installer/.npmrc. This check keeps all of them out of
#    the repository.
#
# What it does not cover: the other files the deploy job uses or reads
# (installer/scripts, installer/src, package.json and its lockfile,
# wrangler.toml), files a step creates while the job runs (the explicit
# flags cover wrangler's config and .env, not npm's), other workflow files,
# and what a pinned action does when it runs.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path
import re
import subprocess

PATH = ".github/workflows/installer-worker.yml"
PINNED = "2c0fa3887f1e0fc59d11baf102ffc442f3a64f4bf8accb2ce730b14d633c9d7c"

CHECKLIST = """\
Before updating PINNED, read the whole diff of this workflow and confirm:
  - `deploy` installs only with `npm ci --ignore-scripts`, in any spelling,
    and runs `wrangler deploy --no-bundle` on the downloaded artifact;
  - `deploy` runs only when `github.ref` starts with `refs/tags/v`, with no
    `||` and no status function in its `if`;
  - every wrangler call passes --config wrangler.toml and --env-file;
  - no job other than `deploy` uses an environment or reads secrets, in any
    YAML or expression form;
  - nothing workflow-wide (env, defaults, run-name, a key placed after
    `jobs:`) changes how `deploy` runs, e.g. BASH_ENV or NODE_OPTIONS;
  - `bundle` still uploads index.js and index.js.map, and no other job
    uploads an artifact with that name."""

# Paths wrangler or npm would read without being told to (see the header).
IMPLICIT = re.compile(
    r"^installer/dist/"
    r"|^(installer/)?(wrangler\.jsonc?|\.wrangler/.*)$"
    r"|^installer/(\.env(\..*)?|\.dev\.vars(\..*)?|\.npmrc)$"
)


def digest(text):
    return sha256(text.replace("\r\n", "\n").encode()).hexdigest()


def implicit(paths):
    return sorted(p for p in paths if IMPLICIT.match(p))


# 1. The pinned workflow.
text = Path(PATH).read_text()
found = digest(text)
if found != PINNED:
    raise SystemExit(f"{PATH} has changed: its SHA-256 is {found}, pinned {PINNED}.\n{CHECKLIST}")
for label, edited in [
    ("a workflow-wide env after the jobs", text + "env:\n  BASH_ENV: x\n"),
    ("a quoted environment key", text.replace("    runs-on: ubuntu-latest\n", '    runs-on: ubuntu-latest\n    "environment": release\n', 1)),
    ("an npm alias", text.replace("npm ci --ignore-scripts", "npm clean-install")),
    ("one changed character", text.replace("retention-days: 7", "retention-days: 8")),
]:
    assert edited != text, f"sample did not change the workflow: {label}"
    assert digest(edited) != PINNED, f"pin accepted: {label}"
assert digest(text.replace("\n", "\r\n")) == PINNED, "CRLF line endings changed the digest"

# 2. Files wrangler or npm would read on their own.
listing = subprocess.run(["git", "ls-files", "-z"], check=True, capture_output=True).stdout
tracked = [p for p in listing.decode().split("\0") if p]
# An empty or partial listing would pass this check silently.
assert PATH in tracked, f"git ls-files did not list {PATH}; the listing is broken"
bad = implicit(tracked)
if bad:
    raise SystemExit(
        "tracked files that wrangler or npm read on their own in installer/:\n  "
        + "\n  ".join(bad)
        + "\nRemove them; installer/wrangler.toml is the only config the deploy uses."
    )
refused = [
    "wrangler.json", "wrangler.jsonc", ".wrangler/deploy/config.json",
    "installer/wrangler.json", "installer/wrangler.jsonc", "installer/.wrangler/deploy/config.json",
    "installer/.env", "installer/.env.local", "installer/.env.production",
    "installer/.dev.vars", "installer/.dev.vars.production", "installer/.npmrc",
    "installer/dist/wrangler.toml", "installer/dist/wrangler.json",
    "installer/dist/.wrangler/deploy/config.json", "installer/dist/index.js",
]
allowed = [
    "installer/wrangler.toml", "installer/src/index.ts", "installer/.env-notes/README.md",
    "crates/x/wrangler.jsonc", "crates/x/.env", "docs/.npmrc", ".npmrc", "installer/src/.env",
]
assert implicit(refused) == sorted(refused), f"not refused: {sorted(set(refused) - set(implicit(refused)))}"
assert implicit(allowed) == [], f"refused by mistake: {implicit(allowed)}"
print("installer deploy: workflow matches its pinned SHA-256; no tracked file wrangler or npm would read on its own")
PY

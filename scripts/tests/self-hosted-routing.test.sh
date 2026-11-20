#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Regression check for where the workflows' jobs run. It reads the
# workflows with patterns written for the layout they use here, not as YAML,
# so it catches the edits a maintainer is likely to make by mistake; it does
# not replace review. For each job in .github/workflows (*.yml, *.yaml), it
# expects runs-on to be one of:
#   - a GitHub-hosted label from HOSTED_LABELS below;
#   - ${{ matrix.<key> }} whose listed values are such labels;
#   - in release.yml only, ${{ matrix.runner }} over the `dist plan` matrix,
#     whose runner set scripts/tests/rebuild-runners.test.sh ties to ci.yml's
#     worker-agents matrix;
#   - the self-hosted routing expression with exactly the conditions below
#     and a GitHub-hosted fallback.
# In a job routed through CI_SELF_HOSTED_LINUX, it expects a step that uses
# an action named like a cache, or passes an input named cache*, to carry
# exactly `if: runner.environment == 'github-hosted'`.
#
# The current workflows must pass, and each weakened copy below must fail.
#
#   scripts/tests/self-hosted-routing.test.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 - <<'PY'
from pathlib import Path
import re

# GitHub-hosted labels these workflows may use. A label GitHub adds goes here
# in the change that first uses it.
HOSTED_LABELS = {
    "ubuntu-latest", "ubuntu-22.04", "ubuntu-22.04-arm", "ubuntu-24.04", "ubuntu-24.04-arm",
    "macos-latest", "macos-14", "macos-15", "macos-15-intel",
    "windows-latest", "windows-2022", "windows-2025",
}

BOTS = "fromJSON('[\"dependabot[bot]\",\"dependabot-preview[bot]\",\"renovate[bot]\"]')"
REQUIRED = sorted(
    [
        "vars.CI_SELF_HOSTED_LINUX != ''",
        "(github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)",
    ]
    + [
        f"!contains({BOTS}, {who})"
        for who in (
            "github.actor",
            "github.triggering_actor",
            "github.event.sender.login",
            "github.event.pull_request.user.login",
        )
    ]
    + [
        f"!contains({ref}, '{prefix}')"
        for ref in ("github.head_ref", "github.ref")
        for prefix in ("dependabot/", "renovate/")
    ]
)
DIST_PLAN_MATRIX = "${{ fromJson(needs.plan.outputs.val).ci.github.artifacts_matrix }}"
HOSTED_ONLY = ("runner.environment == 'github-hosted'", "${{ runner.environment == 'github-hosted' }}")


def code(text):
    """The text without comment-only lines."""
    return "\n".join(line for line in text.split("\n") if not line.lstrip().startswith("#"))


def jobs(text):
    """(name, body) for each job under the top-level `jobs:` key."""
    top = re.search(r"^jobs:\n(.*)", text, re.M | re.S)
    if not top:
        return []
    parts = re.split(r"^  ([A-Za-z0-9_-]+):[ \t]*\n", top[1], flags=re.M)
    return list(zip(parts[1::2], parts[2::2]))


def runs_on(body):
    """The job's runs-on with whitespace collapsed; None without one; '' for
    a block sequence or mapping, which this script does not read."""
    match = re.search(r"^    runs-on:[ \t]*(.*)\n((?:      .*\n|[ \t]*\n)*)", body, re.M)
    if not match:
        return None
    head = match[1].strip()
    if head in (">-", ">", "|", "|-"):
        head = match[2]
    elif head == "":
        return ""
    return " ".join(head.split())


def split_top(expr, op):
    """Split an expression on ` op ` outside parentheses and quotes."""
    parts, depth, quoted, start, i = [], 0, False, 0, 0
    token = f" {op} "
    while i < len(expr):
        c = expr[i]
        if c == "'":
            quoted = not quoted
        elif not quoted and c == "(":
            depth += 1
        elif not quoted and c == ")":
            depth -= 1
        elif not quoted and depth == 0 and expr.startswith(token, i):
            parts.append(expr[start:i])
            i += len(token)
            start = i
            continue
        i += 1
    parts.append(expr[start:])
    return [p.strip() for p in parts]


def matrix_values(body, key):
    """Every value the job's matrix gives `key`, or None if it cannot tell."""
    block = re.search(r"^      matrix:[ \t]*(.*)\n((?:        .*\n|[ \t]*\n)*)", body, re.M)
    if not block:
        return None
    if block[1].strip():
        return None
    values = []
    for inline in re.findall(rf"^        {re.escape(key)}:[ \t]*\[(.*)\][ \t]*$", block[2], re.M):
        values += [v.strip().strip("'\"") for v in inline.split(",") if v.strip()]
    values += [v.strip().strip("'\"") for v in re.findall(rf"^ +(?:- )?{re.escape(key)}:[ \t]*([^\[\n]+)$", block[2], re.M)]
    return values or None


def hosted_label(value, body):
    value = value.strip()
    if re.fullmatch(r"'[^']*'|\"[^\"]*\"", value):
        value = value[1:-1]
    if (value in HOSTED_LABELS):
        return True
    key = re.fullmatch(r"matrix\.([A-Za-z0-9_-]+)", value)
    if key:
        values = matrix_values(body, key[1])
        return bool(values) and all((v in HOSTED_LABELS) for v in values)
    return False


def problems(files):
    found = []
    routed = 0
    for path, text in sorted(files.items()):
        text = code(text)
        read_runs_on, read_mentions = 0, 0
        for name, body in jobs(text):
            where = f"{path}: job {name}"
            value = runs_on(body)
            if value is None:
                continue
            read_runs_on += 1
            read_mentions += value.count("CI_SELF_HOSTED_LINUX")
            if value == "":
                found.append(f"{where}: runs-on is a list or mapping, which this check does not accept")
                continue
            expr = re.fullmatch(r"\$\{\{(.*)\}\}", value)
            if not expr:
                if not hosted_label(value, body):
                    found.append(f"{where}: runs-on {value!r} is not a GitHub-hosted label")
                continue
            inner = expr[1].strip()
            if "CI_SELF_HOSTED_LINUX" not in inner:
                if (
                    path.endswith("/release.yml")
                    and inner == "matrix.runner"
                    and re.search(r"^      matrix: " + re.escape(DIST_PLAN_MATRIX) + r"\s*$", body, re.M)
                ):
                    continue
                if not re.fullmatch(r"matrix\.[A-Za-z0-9_-]+", inner) or not hosted_label(inner, body):
                    found.append(f"{where}: runs-on {value!r} does not resolve to GitHub-hosted labels only")
                continue
            routed += 1
            either = split_top(inner, "||")
            if len(either) != 2:
                found.append(f"{where}: runs-on must be `<conditions> && vars.CI_SELF_HOSTED_LINUX || <hosted label>`")
                continue
            clauses, fallback = split_top(either[0], "&&"), either[1]
            if not hosted_label(fallback, body):
                found.append(f"{where}: the fallback {fallback!r} is not a GitHub-hosted label")
            if clauses[-1] != "vars.CI_SELF_HOSTED_LINUX":
                found.append(f"{where}: the label routed to is not vars.CI_SELF_HOSTED_LINUX")
            clauses = clauses[:-1]
            if clauses and re.fullmatch(r"matrix\.[A-Za-z0-9_-]+ == '[^']*'", clauses[0]):
                clauses = clauses[1:]
            if sorted(clauses) != REQUIRED:
                missing = sorted(set(REQUIRED) - set(clauses))
                extra = sorted(set(clauses) - set(REQUIRED))
                found.append(f"{where}: routing conditions differ (missing {missing}, unexpected {extra})")
            for step in re.split(r"^      - ", body, flags=re.M)[1:]:
                uses = re.search(r"^(?:      )?\s*uses:[ \t]*['\"]?([^'\"\s]+)", step, re.M)
                caches = (uses and re.search("cache", uses[1], re.I)) or re.search(r"^\s+cache[A-Za-z-]*:", step, re.M)
                if not caches:
                    continue
                cond = re.search(r"^(?:\s*)if:[ \t]*(.*?)[ \t]*$", step, re.M)
                if not cond or cond[1] not in HOSTED_ONLY:
                    found.append(f"{where}: a cache step can run on the self-hosted runners")
        if len(re.findall(r"^\s*-?\s*runs-on:", text, re.M)) != read_runs_on:
            found.append(f"{path}: has a runs-on this check cannot read")
        if text.count("CI_SELF_HOSTED_LINUX") != read_mentions:
            found.append(f"{path}: mentions CI_SELF_HOSTED_LINUX outside a runs-on this check read")
    if not routed:
        found.append("no job is routed through CI_SELF_HOSTED_LINUX; update this check with the workflows")
    return found


root = Path(".github/workflows")
workflows = {str(p): p.read_text() for p in sorted([*root.glob("*.yml"), *root.glob("*.yaml")])}
actual = problems(workflows)
assert not actual, "the workflows fail the runner check:\n" + "\n".join(actual)

CI = ".github/workflows/ci.yml"
PUBLISH = ".github/workflows/release-publish.yml"
RELEASE = ".github/workflows/release.yml"


def mutated(path, old, new, count=-1):
    text = workflows[path]
    assert old in text, f"mutation source not found in {path}: {old!r}"
    return {**workflows, path: text.replace(old, new, count)}


def added(path, text):
    return {**workflows, path: text}


CACHE_IF = "      - if: runner.environment == 'github-hosted'\n        uses: Swatinem/rust-cache@"
bad = {
    "fork condition dropped": mutated(
        CI, "&& (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)\n", ""),
    "conditions bypassed with ||": mutated(
        CI, "&& vars.CI_SELF_HOSTED_LINUX || 'ubuntu-latest'", "|| true && vars.CI_SELF_HOSTED_LINUX || 'ubuntu-latest'"),
    "an extra condition": mutated(
        CI, "&& !contains(github.ref, 'renovate/')", "&& !contains(github.ref, 'renovate/') && github.run_attempt == 1", 1),
    "a condition negated twice": mutated(CI, f"&& !contains({BOTS}, github.actor)", f"&& !!contains({BOTS}, github.actor)", 1),
    "clippy falls back to the runners": mutated(
        CI, "&& vars.CI_SELF_HOSTED_LINUX || 'ubuntu-latest'", "&& vars.CI_SELF_HOSTED_LINUX || vars.CI_SELF_HOSTED_LINUX"),
    "test falls back to the runners": mutated(
        CI, "&& vars.CI_SELF_HOSTED_LINUX || matrix.os", "&& vars.CI_SELF_HOSTED_LINUX || vars.CI_SELF_HOSTED_LINUX"),
    "a runner label in the routed matrix": mutated(
        CI, "os: [ubuntu-latest, macos-latest, windows-latest]", "os: [ubuntu-latest, macos-latest, windows-latest, self-hosted]"),
    "a runner label in a hosted matrix": mutated(
        CI, "runner: [ubuntu-22.04, ubuntu-22.04-arm, macos-15, windows-2022]",
        "runner: [ubuntu-22.04, ubuntu-22.04-arm, macos-15, windows-2022, self-hosted]"),
    "a runner label in a matrix include": mutated(PUBLISH, "runner: ubuntu-22.04-arm", "runner: self-hosted"),
    "a matrix this check cannot read": mutated(RELEASE, DIST_PLAN_MATRIX, "${{ fromJson(inputs.matrix) }}"),
    "rust-cache unguarded": mutated(CI, CACHE_IF, "      - uses: Swatinem/rust-cache@", 1),
    "rust-cache guard weakened": mutated(
        CI, CACHE_IF, "      - if: runner.environment == 'github-hosted' || true\n        uses: Swatinem/rust-cache@", 1),
    "rust-cache quoted and unguarded": mutated(CI, CACHE_IF, "      - uses: \"Swatinem/rust-cache@", 1),
    "an unguarded actions/cache step": mutated(
        CI, "      - run: cargo clippy", "      - uses: actions/cache@0000000000000000000000000000000000000000\n      - run: cargo clippy"),
    "an unguarded cache input": mutated(
        CI, "      - run: cargo clippy",
        "      - uses: actions/setup-node@0000000000000000000000000000000000000000\n        with:\n          cache: npm\n      - run: cargo clippy"),
    "a runner label written directly": mutated(CI, "  fmt:\n    name: rustfmt\n    runs-on: ubuntu-latest",
                                                  "  fmt:\n    name: rustfmt\n    runs-on: self-hosted"),
    "runs-on as a list": mutated(CI, "  fmt:\n    name: rustfmt\n    runs-on: ubuntu-latest",
                                  "  fmt:\n    name: rustfmt\n    runs-on:\n      - self-hosted"),
    "runs-on as a mapping": mutated(CI, "  fmt:\n    name: rustfmt\n    runs-on: ubuntu-latest",
                                     "  fmt:\n    name: rustfmt\n    runs-on:\n      labels: [some-runner]"),
    "a .yaml workflow": added(".github/workflows/extra.yaml",
                              "on: push\njobs:\n  x:\n    runs-on: self-hosted\n    steps:\n      - run: true\n"),
    "a workflow indented by four": added(".github/workflows/extra.yml",
                                         "on: push\njobs:\n    x:\n        runs-on: ${{ vars.CI_SELF_HOSTED_LINUX }}\n"),
    "the dist plan matrix outside release.yml": added(
        ".github/workflows/extra.yml",
        "on: push\njobs:\n  build:\n    strategy:\n      matrix: " + DIST_PLAN_MATRIX + "\n    runs-on: ${{ matrix.runner }}\n"),
    "a label GitHub does not host": mutated(CI, "  fmt:\n    name: rustfmt\n    runs-on: ubuntu-latest",
                                            "  fmt:\n    name: rustfmt\n    runs-on: ubuntu-1"),
}
for who in ("github.actor", "github.triggering_actor", "github.event.sender.login", "github.event.pull_request.user.login"):
    bad[f"bot check on {who} dropped"] = mutated(CI, f"&& !contains({BOTS}, {who})\n", "")
for ref in ("github.head_ref", "github.ref"):
    for prefix in ("dependabot/", "renovate/"):
        bad[f"{prefix} check on {ref} dropped"] = mutated(CI, f"!contains({ref}, '{prefix}')", "true")

accepted = [name for name, files in bad.items() if not problems(files)]
assert not accepted, "the check accepted weakened workflows: " + ", ".join(accepted)
print(f"runner check: workflows pass; {len(bad)} weakened copies rejected")
PY

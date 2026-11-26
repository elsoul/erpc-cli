// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

/**
 * What the worker checks and adds to an installer body. Kept apart from
 * src/index.ts, and free of imports, so that
 * installer/scripts/verify-against-real-installers.mjs can load it in CI
 * without the worker's npm dependencies.
 */

/**
 * What runs after the installer: `erpc skills install`, with the binary the
 * installer put in place. cargo-dist's installers end by calling their main
 * function (`download_binary_and_run_installer "$@" || exit 1`, and
 * `Install-Binary` in a try/catch), so a tail runs after a successful
 * install and not after a failed one. The binary is looked for where the
 * generated installer puts it, in its order of precedence: with
 * `ERPC_INSTALL_DIR`, `CARGO_DIST_FORCE_INSTALL_DIR` or
 * `ERPC_UNMANAGED_INSTALL` set, in that directory itself (cargo-dist's
 * "flat" layout; under `bin/` only when the directory is Cargo's home), and
 * otherwise in `~/.erpc/bin` (dist-workspace.toml). An earlier tail looked
 * under `bin/` for the first two and so ran a binary from an earlier
 * install; `installer/scripts/verify-against-real-installers.mjs` now pins
 * the layout and the endings this tail depends on. A failure here never
 * fails the install: `erpc skills install` can be run again by hand.
 */
export const AFTER_INSTALL: Record<"sh" | "ps1", string> = {
  sh: `
# erpc: put the assistant's skills on this machine (~/.erpc/skills), with the
# binary the installer above put in place: in the forced directory itself
# (bin/ only when that directory is Cargo's home), else in ~/.erpc/bin.
for _erpc_dir in "\${ERPC_INSTALL_DIR:-}" "\${CARGO_DIST_FORCE_INSTALL_DIR:-}" \\
    "\${ERPC_UNMANAGED_INSTALL:-}" "$HOME/.erpc/bin"; do
  [ -n "$_erpc_dir" ] || continue
  for _erpc_bin in "$_erpc_dir/erpc" "$_erpc_dir/bin/erpc"; do
    if [ -x "$_erpc_bin" ]; then
      "$_erpc_bin" skills install || say "could not write the skills; run: erpc skills install"
      break 2
    fi
  done
done
`,
  ps1: `
# erpc: put the assistant's skills on this machine (~/.erpc/skills), with the
# binary the installer above put in place: in the forced directory itself
# (bin\\ only when that directory is Cargo's home), else in ~/.erpc/bin.
$erpcDirs = @()
foreach ($erpcForced in @($env:ERPC_INSTALL_DIR, $env:CARGO_DIST_FORCE_INSTALL_DIR, $env:ERPC_UNMANAGED_INSTALL)) {
  if ($erpcForced) { $erpcDirs += $erpcForced }
}
$erpcDirs += Join-Path $HOME ".erpc\\bin"
:erpcFound foreach ($erpcDir in $erpcDirs) {
  foreach ($erpcBin in @((Join-Path $erpcDir "erpc.exe"), (Join-Path $erpcDir "bin\\erpc.exe"))) {
    if (Test-Path -LiteralPath $erpcBin -PathType Leaf) {
      & $erpcBin skills install
      if ($LASTEXITCODE -ne 0) { Write-Information "could not write the skills; run: erpc skills install" }
      break erpcFound
    }
  }
}
`,
};

/**
 * The installer, with [`AFTER_INSTALL`] after it. `trimEnd`, not a `\s*$`
 * regex: on a body that is not ours a backtracking regex over runs of
 * whitespace is polynomial, and CodeQL says so.
 */
export function withAfterInstall(body: string, flavor: "sh" | "ps1"): string {
  return `${body.trimEnd()}\n${AFTER_INSTALL[flavor]}`;
}

/**
 * A sanity check, not a security control: it rejects markup and an empty
 * body, so a 404 page becomes a clear 502 rather than being piped into a
 * shell. A plain-text or markdown error body opening with `#` is accepted
 * for the PowerShell flavour, because the real installer opens that way too.
 *
 * The shapes are those of the installers cargo-dist actually generates, taken
 * from `dist build --artifacts=global` output rather than from the template:
 * the shell installer starts with `#!/bin/sh`, and the PowerShell one starts
 * with a run of `#` licence comments, reaching its `<#` block several lines
 * in. An earlier version of this function required `<#` at position 0 and
 * would have rejected every real PowerShell installer.
 */
export function looksLikeInstaller(body: string, flavor: "sh" | "ps1"): boolean {
  const head = body.slice(0, 512).trimStart();
  if (head.length === 0) return false;
  // Any markup is an error page, whatever it claims to be.
  if (/^<(!|html|\?xml)/i.test(head)) return false;
  if (flavor === "sh") return head.startsWith("#!");
  return head.startsWith("#") || head.startsWith("<#");
}

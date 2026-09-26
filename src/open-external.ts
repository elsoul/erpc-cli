// Hands a URL to the platform's browser launcher.
//
// `open` (macOS) and `xdg-open` receive the URL as a single argument. On
// Windows the URL goes through `cmd /c start "" <url>`, and cmd parses that
// command line again: `&`, `|`, `<`, `>` and `^` are operators to it, `"`
// changes its quoting, `%NAME%` expands an environment variable (and so does
// `!NAME!` when delayed expansion is turned on), and a string that is not a
// URL can start a program. So on Windows only an http(s) URL whose serialized
// form stays inside a conservative subset of URL characters is handed over.
// Any other URL is not opened; every caller prints the URL before it calls
// the launcher.

/**
 * URL characters that cmd reads as plain text. `%` and `!` are left out as
 * well, so neither a percent-encoded byte, `%NAME%`, nor `!NAME!` (expanded
 * when delayed expansion is on) reaches cmd.
 */
const SHELL_SAFE_URL_PATTERN = /^[A-Za-z0-9._~:/?#\[\]@$'()*+,;=-]*$/

/** Whether every character of `value` is in the conservative URL subset. */
export const isShellSafeUrl = (value: string): boolean =>
  SHELL_SAFE_URL_PATTERN.test(value)

export interface OpenExternalDeps {
  /** Defaults to `Deno.build.os`. */
  readonly os?: typeof Deno.build.os
  /** Starts `command` with `args`, detached from the CLI. */
  readonly spawn?: (command: string, args: readonly string[]) => void
}

const spawnDetached = (command: string, args: readonly string[]): void => {
  const child = new Deno.Command(command, {
    args: [...args],
    stdin: 'null',
    stdout: 'null',
    stderr: 'null',
  }).spawn()
  child.unref()
}

/** The URL `start` may receive, or `undefined` when it must not be opened. */
const windowsLaunchableUrl = (url: string): string | undefined => {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return undefined
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return undefined
  }
  return isShellSafeUrl(parsed.href) ? parsed.href : undefined
}

/**
 * Opens `url` in the default browser. Returns whether a launcher was started;
 * `false` means the URL is left for the user to open from the printed text.
 */
export const openExternalUrl = (
  url: string,
  deps: OpenExternalDeps = {},
): boolean => {
  const os = deps.os ?? Deno.build.os
  let command: string
  let args: readonly string[]
  if (os === 'darwin') {
    command = 'open'
    args = [url]
  } else if (os === 'windows') {
    const launchable = windowsLaunchableUrl(url)
    if (launchable === undefined) return false
    command = 'cmd'
    args = ['/c', 'start', '', launchable]
  } else {
    command = 'xdg-open'
    args = [url]
  }
  try {
    ;(deps.spawn ?? spawnDetached)(command, args)
    return true
  } catch {
    // The URL is always printed, so browser launch is best effort.
    return false
  }
}

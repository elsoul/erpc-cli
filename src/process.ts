export interface ProcessRequest {
  readonly args: readonly string[]
  readonly command: string
  readonly cwd?: string
  readonly display?: boolean
  /**
   * Extra environment variables for the child process. Merged on top of the
   * parent's inherited environment (Deno.Command's default `clearEnv: false`
   * behavior), so a caller-supplied value always wins over whatever the
   * parent shell happened to export.
   */
  readonly env?: Readonly<Record<string, string>>
  readonly input?: string
  /**
   * `'piped'` (default) captures stdout/stderr into the returned result, and
   * pipes `input` to stdin when present. `'inherit'` shares the parent's
   * stdin/stdout/stderr directly - used for an interactive child (`wrangler
   * login`) or one whose own streamed output should reach the terminal
   * as-is (`wrangler deploy`); its result always reports empty
   * stdout/stderr.
   */
  readonly stdio?: 'inherit' | 'piped'
}

export interface ProcessResult {
  readonly code: number
  readonly stderr: string
  readonly stdout: string
}

export type ProcessRunner = (
  request: ProcessRequest,
) => Promise<ProcessResult>

const decoder = new TextDecoder()
const encoder = new TextEncoder()

export const runProcess: ProcessRunner = async (request) => {
  const inherit = request.stdio === 'inherit'
  let child: Deno.ChildProcess
  try {
    child = new Deno.Command(request.command, {
      args: [...request.args],
      ...(request.cwd === undefined ? {} : { cwd: request.cwd }),
      ...(request.env === undefined ? {} : { env: { ...request.env } }),
      stdin: inherit
        ? 'inherit'
        : request.input === undefined
        ? 'null'
        : 'piped',
      stdout: inherit ? 'inherit' : 'piped',
      stderr: inherit ? 'inherit' : 'piped',
    }).spawn()
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    throw new Error(`Unable to start ${request.command}: ${message}`)
  }

  if (!inherit && request.input !== undefined) {
    const writer = child.stdin.getWriter()
    await writer.write(encoder.encode(request.input))
    await writer.close()
  }
  if (inherit) {
    const status = await child.status
    return { code: status.code, stderr: '', stdout: '' }
  }
  const result = await child.output()
  if (request.display) {
    await Deno.stdout.write(result.stdout)
    await Deno.stderr.write(result.stderr)
  }
  return {
    code: result.code,
    stderr: decoder.decode(result.stderr),
    stdout: decoder.decode(result.stdout),
  }
}

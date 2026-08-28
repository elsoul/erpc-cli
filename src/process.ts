export interface ProcessRequest {
  readonly args: readonly string[]
  readonly command: string
  readonly cwd?: string
  readonly display?: boolean
  readonly input?: string
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
  let child: Deno.ChildProcess
  try {
    child = new Deno.Command(request.command, {
      args: [...request.args],
      ...(request.cwd === undefined ? {} : { cwd: request.cwd }),
      stdin: request.input === undefined ? 'null' : 'piped',
      stdout: 'piped',
      stderr: 'piped',
    }).spawn()
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    throw new Error(`Unable to start ${request.command}: ${message}`)
  }

  if (request.input !== undefined) {
    const writer = child.stdin.getWriter()
    await writer.write(encoder.encode(request.input))
    await writer.close()
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

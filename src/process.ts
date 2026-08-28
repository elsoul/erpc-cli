import { spawn } from 'node:child_process'

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

export const runProcess: ProcessRunner = async (request) =>
  await new Promise<ProcessResult>((resolve, reject) => {
    const child = spawn(request.command, [...request.args], {
      ...(request.cwd === undefined ? {} : { cwd: request.cwd }),
      env: process.env,
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    const stdout: Buffer[] = []
    const stderr: Buffer[] = []

    child.stdout.on('data', (chunk: Buffer) => {
      stdout.push(chunk)
      if (request.display) process.stdout.write(chunk)
    })
    child.stderr.on('data', (chunk: Buffer) => {
      stderr.push(chunk)
      if (request.display) process.stderr.write(chunk)
    })
    child.once('error', (error) => {
      reject(new Error(`Unable to start ${request.command}: ${error.message}`))
    })
    child.once('close', (code) => {
      resolve({
        code: code ?? 1,
        stderr: Buffer.concat(stderr).toString('utf8'),
        stdout: Buffer.concat(stdout).toString('utf8'),
      })
    })

    if (request.input === undefined) child.stdin.end()
    else child.stdin.end(request.input)
  })

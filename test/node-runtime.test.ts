import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from './testing.ts'
import {
  NODE_RUNTIME_VERSION,
  type ProcessRunner,
  resolveVerifiedNodeRuntime,
} from '../src/index.ts'

const directories: string[] = []

afterEach(async () => {
  await Promise.all(
    directories.splice(0).map((directory) =>
      rm(directory, { force: true, recursive: true })
    ),
  )
})

const sha256 = async (bytes: Uint8Array): Promise<string> => {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', copy))
  return [...digest]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

describe('verified Node.js deployment runtime', () => {
  it('checks the archive digest before extracting an application-local runtime', async () => {
    const erpcHome = await mkdtemp(join(tmpdir(), 'erpc-node-runtime-'))
    directories.push(erpcHome)
    const archive = new TextEncoder().encode('verified archive')
    const fileName = `node-v${NODE_RUNTIME_VERSION}-linux-x64.tar.xz`
    const checksum = await sha256(archive)
    const fetched: string[] = []
    const fetch = async (input: string | URL | Request) => {
      const url = String(input)
      fetched.push(url)
      return url.endsWith('SHASUMS256.txt')
        ? new Response(`${checksum}  ${fileName}\n`)
        : new Response(archive)
    }
    const run: ProcessRunner = async (request) => {
      const destination = request.args[request.args.indexOf('-C') + 1]
      if (!destination) throw new Error('missing extraction destination')
      await mkdir(destination, { recursive: true })
      await writeFile(join(destination, 'node'), 'runtime')
      return { code: 0, stderr: '', stdout: '' }
    }

    const runtime = await resolveVerifiedNodeRuntime('x64', erpcHome, {
      fetch,
      run,
    })

    expect(runtime).toContain(`v${NODE_RUNTIME_VERSION}`)
    expect(fetched).toHaveLength(2)
  })
})

import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises'
import { constants } from 'node:fs'
import { join } from 'node:path'
import { type ProcessRunner, runProcess } from '../process.ts'
import type { LinuxArchitecture } from './build.ts'

export const NODE_RUNTIME_VERSION = '24.20.0'
const NODE_DISTRIBUTION = `https://nodejs.org/dist/v${NODE_RUNTIME_VERSION}`

export interface NodeRuntimeOptions {
  readonly fetch?: typeof globalThis.fetch
  readonly run?: ProcessRunner
}

const hexadecimal = (bytes: ArrayBuffer): string =>
  [...new Uint8Array(bytes)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')

const sha256 = async (bytes: Uint8Array): Promise<string> => {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return hexadecimal(await crypto.subtle.digest('SHA-256', copy))
}

const regularFile = async (path: string): Promise<boolean> => {
  try {
    return (await stat(path)).isFile()
  } catch {
    return false
  }
}

export const resolveVerifiedNodeRuntime = async (
  architecture: LinuxArchitecture,
  erpcHome: string,
  options: NodeRuntimeOptions = {},
): Promise<string> => {
  const fetcher = options.fetch ?? globalThis.fetch
  const runner = options.run ?? runProcess
  const platformArchitecture = architecture === 'x64' ? 'x64' : 'arm64'
  const fileName =
    `node-v${NODE_RUNTIME_VERSION}-linux-${platformArchitecture}.tar.xz`
  const cacheDirectory = join(
    erpcHome,
    'cache',
    'node',
    `v${NODE_RUNTIME_VERSION}`,
    `linux-${platformArchitecture}`,
  )
  const archivePath = join(cacheDirectory, fileName)
  const runtimePath = join(cacheDirectory, 'node')
  await mkdir(cacheDirectory, { mode: 0o700, recursive: true })
  if (await regularFile(runtimePath)) return await realpath(runtimePath)

  const checksumsResponse = await fetcher(`${NODE_DISTRIBUTION}/SHASUMS256.txt`)
  if (!checksumsResponse.ok) {
    throw new Error('Unable to download Node.js runtime checksums')
  }
  const checksumLine = (await checksumsResponse.text())
    .split(/\r?\n/)
    .find((line) => line.endsWith(`  ${fileName}`))
  const expected = checksumLine?.split(/\s+/)[0]
  if (!expected || !/^[a-f0-9]{64}$/.test(expected)) {
    throw new Error('The Node.js runtime checksum manifest is invalid')
  }

  let archive: Uint8Array
  if (await regularFile(archivePath)) {
    archive = await readFile(archivePath)
  } else {
    const archiveResponse = await fetcher(`${NODE_DISTRIBUTION}/${fileName}`)
    if (!archiveResponse.ok) {
      throw new Error('Unable to download the Node.js runtime')
    }
    archive = new Uint8Array(await archiveResponse.arrayBuffer())
    if (await sha256(archive) !== expected) {
      throw new Error(
        'The downloaded Node.js runtime failed checksum verification',
      )
    }
    try {
      await writeFile(archivePath, archive, { flag: 'wx', mode: 0o600 })
    } catch (error) {
      if (
        !(error instanceof Error && 'code' in error && error.code === 'EEXIST')
      ) {
        throw error
      }
      archive = await readFile(archivePath)
    }
  }
  if (await sha256(archive) !== expected) {
    throw new Error(
      'The cached Node.js runtime archive failed checksum verification',
    )
  }

  const extraction = await mkdtemp(join(cacheDirectory, '.extract-'))
  try {
    const result = await runner({
      args: [
        '-xJf',
        archivePath,
        '-C',
        extraction,
        '--strip-components=2',
        `node-v${NODE_RUNTIME_VERSION}-linux-${platformArchitecture}/bin/node`,
      ],
      command: 'tar',
    })
    const extracted = join(extraction, 'node')
    if (result.code !== 0 || !(await regularFile(extracted))) {
      throw new Error('Unable to extract the verified Node.js runtime')
    }
    try {
      await copyFile(extracted, runtimePath, constants.COPYFILE_EXCL)
    } catch (error) {
      if (
        !(error instanceof Error && 'code' in error && error.code === 'EEXIST')
      ) {
        throw error
      }
    }
    await chmod(runtimePath, 0o700)
    return await realpath(runtimePath)
  } finally {
    await rm(extraction, { force: true, recursive: true })
  }
}

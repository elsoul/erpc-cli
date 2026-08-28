import { lstat, open, realpath } from 'node:fs/promises'
import { relative, resolve } from 'node:path'
import type { ErpcManifest } from '../app/manifest'
import { runProcess, type ProcessRunner } from '../process'

export type LinuxArchitecture = 'arm64' | 'x64'

export interface BuildArtifact {
  readonly architecture?: LinuxArchitecture
  readonly path: string
  readonly runtime: ErpcManifest['app']['runtime']
}

export interface BuildOptions {
  readonly run?: ProcessRunner
}

const containedPath = (root: string, path: string): boolean => {
  const child = relative(root, path)
  return child !== '..' && !child.startsWith('../') && !child.startsWith('..\\')
}

const elfArchitecture = async (path: string): Promise<LinuxArchitecture> => {
  const handle = await open(path, 'r')
  try {
    const header = Buffer.alloc(20)
    const { bytesRead } = await handle.read(header, 0, header.length, 0)
    if (
      bytesRead < 20 ||
      header[0] !== 0x7f ||
      header.subarray(1, 4).toString('ascii') !== 'ELF' ||
      header[5] !== 1
    ) throw new Error('Deno build artifact must be a little-endian Linux ELF binary')
    const machine = header.readUInt16LE(18)
    if (machine === 62) return 'x64'
    if (machine === 183) return 'arm64'
    throw new Error(`Unsupported Linux artifact architecture: ${machine}`)
  } finally {
    await handle.close()
  }
}

export const buildForDeployment = async (
  manifest: ErpcManifest,
  options: BuildOptions = {},
): Promise<BuildArtifact> => {
  const [program, ...args] = manifest.build.command
  if (!program) throw new Error('build.command is empty')
  const result = await (options.run ?? runProcess)({
    args,
    command: program,
    cwd: manifest.projectRoot,
    display: true,
  })
  if (result.code !== 0) {
    throw new Error('Local build failed; no deployment connection was attempted')
  }

  const artifact = resolve(manifest.projectRoot, manifest.build.artifact)
  if (!containedPath(manifest.projectRoot, artifact)) {
    throw new Error('Build artifact escaped the application root')
  }
  const info = await lstat(artifact).catch(() => null)
  if (!info?.isFile() || info.isSymbolicLink()) {
    throw new Error('Local build succeeded but its artifact is missing or unsafe')
  }
  const canonicalRoot = await realpath(manifest.projectRoot)
  const canonicalArtifact = await realpath(artifact)
  if (!containedPath(canonicalRoot, canonicalArtifact)) {
    throw new Error('Build artifact resolves outside the application root')
  }
  return {
    path: canonicalArtifact,
    runtime: manifest.app.runtime,
    ...(manifest.app.runtime === 'deno'
      ? { architecture: await elfArchitecture(canonicalArtifact) }
      : {}),
  }
}

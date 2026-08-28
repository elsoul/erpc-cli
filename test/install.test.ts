import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from './testing.ts'

const directories: string[] = []

afterEach(async () => {
  await Promise.all(
    directories.splice(0).map((directory) =>
      rm(directory, { force: true, recursive: true })
    ),
  )
})

const command = async (program: string, args: string[], cwd: string) =>
  await new Deno.Command(program, {
    args,
    cwd,
    stderr: 'piped',
    stdout: 'piped',
  }).output()

describe('standalone installer', () => {
  it.each([
    ['Linux', 'x86_64', 'x86_64-unknown-linux-gnu'],
    ['Darwin', 'arm64', 'aarch64-apple-darwin'],
  ])('selects and verifies the %s %s binary', async (
    operatingSystem: string,
    architecture: string,
    target: string,
  ) => {
    const root = await mkdtemp(join(tmpdir(), 'erpc-installer-'))
    directories.push(root)
    const release = join(root, 'release')
    const versionDirectory = join(release, 'erpc', 'v0.2.0')
    const source = join(root, 'source')
    const fakeBin = join(root, 'fake-bin')
    const installDirectory = join(root, 'installed')
    await mkdir(versionDirectory, { recursive: true })
    await mkdir(source)
    await mkdir(fakeBin)
    await writeFile(join(release, 'erpc', 'latest'), 'v0.2.0\n')
    await writeFile(
      join(source, 'erpc'),
      '#!/bin/sh\n[ "${1:-}" = "--version" ] && printf "0.2.0\\n"\n',
      { mode: 0o755 },
    )
    const archiveName = `erpc-${target}.tar.gz`
    const archivePath = join(versionDirectory, archiveName)
    const packed = await command('tar', [
      '-C',
      source,
      '-czf',
      archivePath,
      'erpc',
    ], root)
    expect(packed.code).toBe(0)
    const digest = await command('sha256sum', [archivePath], root)
    expect(digest.code).toBe(0)
    const checksum = new TextDecoder().decode(digest.stdout).split(/\s+/)[0]
    await writeFile(
      join(versionDirectory, 'SHA256SUMS'),
      `${checksum}  ${archiveName}\n`,
    )
    const fakeCurl = join(fakeBin, 'curl')
    await writeFile(
      fakeCurl,
      `#!/bin/sh
output=''
url=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --proto | --proto-redir) shift 2 ;;
    --tlsv1.2) shift ;;
    -o) output="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
path="\${url#https://storage.test}"
source="\${ERPC_TEST_RELEASE_ROOT}\${path}"
if [ -n "$output" ]; then cp "$source" "$output"; else cp "$source" /dev/stdout; fi
`,
    )
    await chmod(fakeCurl, 0o755)
    const fakeUname = join(fakeBin, 'uname')
    await writeFile(
      fakeUname,
      `#!/bin/sh
case "\${1:-}" in
  -s) printf '%s\n' "\${ERPC_TEST_OS}" ;;
  -m) printf '%s\n' "\${ERPC_TEST_ARCH}" ;;
  *) exit 1 ;;
esac
`,
    )
    await chmod(fakeUname, 0o755)

    const runInstaller = async () =>
      await new Deno.Command('sh', {
        args: ['install'],
        cwd: new URL('..', import.meta.url),
        env: {
          ERPC_INSTALL_DIR: installDirectory,
          ERPC_RELEASE_BASE_URL: 'https://storage.test/erpc',
          ERPC_TEST_RELEASE_ROOT: release,
          ERPC_TEST_ARCH: architecture,
          ERPC_TEST_OS: operatingSystem,
          PATH: `${fakeBin}:${Deno.env.get('PATH') ?? ''}`,
        },
        stderr: 'piped',
        stdout: 'piped',
      }).output()

    const installed = await runInstaller()

    expect(installed.code).toBe(0)
    expect(new TextDecoder().decode(installed.stdout)).toContain(
      'Installed erpc 0.2.0',
    )
    expect(await readFile(join(installDirectory, 'erpc'), 'utf8')).toContain(
      'printf "0.2.0',
    )

    await writeFile(archivePath, 'tampered archive')
    const rejected = await runInstaller()
    expect(rejected.code).not.toBe(0)
    expect(new TextDecoder().decode(rejected.stderr)).toContain(
      'binary checksum verification failed',
    )
  })
})

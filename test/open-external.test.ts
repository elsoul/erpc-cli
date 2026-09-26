import { assert, assertEquals } from '@std/assert'
import { describe, it } from './testing.ts'
import { isShellSafeUrl, openExternalUrl } from '../src/open-external.ts'

const PAGE = 'https://broker.example.com/register?user_code=BCDF-GHJK'

const recorder = () => {
  const started: Array<readonly [string, readonly string[]]> = []
  return {
    spawn: (command: string, args: readonly string[]) => {
      started.push([command, [...args]])
    },
    started,
  }
}

describe('openExternalUrl', () => {
  it('starts no process on Windows for a URL that cmd would reinterpret', () => {
    for (
      const url of [
        `${PAGE}&calc`,
        'https://broker.example.com/register?u=%USERNAME%',
        'https://broker.example.com/register?u=x|x^y',
        'https://x&calc.example.com/register?user_code=BCDF-GHJK',
        'https://broker.example.com/register?u=<x>',
        'https://broker.example.com/register?u="x"',
      ]
    ) {
      const launcher = recorder()
      assertEquals(
        openExternalUrl(url, { os: 'windows', spawn: launcher.spawn }),
        false,
        url,
      )
      assertEquals(launcher.started, [], url)
    }
  })

  it('starts no process on Windows for a value that is not an http(s) URL', () => {
    for (
      const url of [
        'calc',
        'calc.exe',
        'file:///C:/Windows/System32/calc.exe',
        'ms-settings:',
      ]
    ) {
      const launcher = recorder()
      assertEquals(
        openExternalUrl(url, { os: 'windows', spawn: launcher.spawn }),
        false,
        url,
      )
      assertEquals(launcher.started, [], url)
    }
  })

  it('starts cmd exactly once on Windows for a plain https URL', () => {
    const launcher = recorder()
    assertEquals(
      openExternalUrl(PAGE, { os: 'windows', spawn: launcher.spawn }),
      true,
    )
    assertEquals(launcher.started, [['cmd', ['/c', 'start', '', PAGE]]])
  })

  it('hands the URL unchanged to open on macOS and xdg-open elsewhere', () => {
    const url = `${PAGE}&x=%41`
    for (
      const [os, command] of [
        ['darwin', 'open'],
        ['linux', 'xdg-open'],
      ] as const
    ) {
      const launcher = recorder()
      assertEquals(openExternalUrl(url, { os, spawn: launcher.spawn }), true)
      assertEquals(launcher.started, [[command, [url]]])
    }
  })

  it('reports false when the launcher cannot be started', () => {
    assertEquals(
      openExternalUrl(PAGE, {
        os: 'linux',
        spawn: () => {
          throw new Error('not found')
        },
      }),
      false,
    )
  })
})

describe('isShellSafeUrl', () => {
  it('accepts the fixed approval page and refuses cmd metacharacters and %', () => {
    assert(isShellSafeUrl(PAGE))
    for (const character of ['&', '|', '^', '<', '>', '"', '%', ' ', '`']) {
      assert(!isShellSafeUrl(`${PAGE}${character}`), character)
    }
  })
})

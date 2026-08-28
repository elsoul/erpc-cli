import { describe, expect, it } from './testing.ts'
import { renderErpcWelcomeArt, runCli, stripAnsi } from '../src/index.ts'

describe('CLI welcome UI', () => {
  it('renders the ERPC welcome art within the terminal width', () => {
    const art = stripAnsi(renderErpcWelcomeArt(42))

    expect(art).toContain('Welcome to ERPC v0.2.1')
    for (const line of art.split('\n')) expect(line.length <= 42).toBe(true)
  })

  it('prints the welcome art and primary commands', async () => {
    const output: string[] = []

    await expect(runCli(['--print'], {
      output: (message) => output.push(message),
    })).resolves.toBe(0)

    const text = stripAnsi(output.join('\n'))
    expect(text).toContain('Welcome to ERPC v0.2.1')
    expect(text).toContain('$ erpc login')
    expect(text).toContain('$ erpc app init')
    expect(text).toContain('$ erpc deploy')
  })

  it('uses generated command help', async () => {
    const output: string[] = []

    await expect(runCli(['--help'], {
      output: (message) => output.push(message),
    })).resolves.toBe(0)

    const text = stripAnsi(output.join('\n'))
    expect(text).toContain('Usage:')
    expect(text).toContain('Commands:')
    expect(text).toContain('login')
    expect(text).toContain('resources')
    expect(text).toContain('deploy')
  })
})

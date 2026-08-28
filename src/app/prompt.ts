import { createInterface } from 'node:readline/promises'
import { stdin, stdout } from 'node:process'
import type { AppRuntime } from './templates'

export const promptForRuntime = async (): Promise<AppRuntime> => {
  if (!stdin.isTTY || !stdout.isTTY) {
    throw new Error('Use --runtime node or --runtime deno in non-interactive mode')
  }
  const prompt = createInterface({ input: stdin, output: stdout })
  try {
    const answer = await prompt.question(
      'Choose a runtime:\n  1. Node.js with pnpm\n  2. Deno\nRuntime [1]: ',
    )
    const normalized = answer.trim().toLowerCase()
    if (!normalized || normalized === '1' || normalized === 'node') return 'node'
    if (normalized === '2' || normalized === 'deno') return 'deno'
    throw new Error('Runtime must be node or deno')
  } finally {
    prompt.close()
  }
}

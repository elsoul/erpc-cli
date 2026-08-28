import type { AppRuntime } from './templates.ts'

export const promptForRuntime = async (): Promise<AppRuntime> => {
  if (!Deno.stdin.isTerminal() || !Deno.stdout.isTerminal()) {
    throw new Error(
      'Use --runtime node or --runtime deno in non-interactive mode',
    )
  }
  const answer = globalThis.prompt(
    'Choose a runtime:\n  1. Node.js with pnpm\n  2. Deno\nRuntime [1]:',
  ) ?? ''
  const normalized = answer.trim().toLowerCase()
  if (!normalized || normalized === '1' || normalized === 'node') return 'node'
  if (normalized === '2' || normalized === 'deno') return 'deno'
  throw new Error('Runtime must be node or deno')
}

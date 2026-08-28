import { runCli } from './cli.ts'

if (import.meta.main) {
  try {
    Deno.exit(await runCli(Deno.args))
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'ERPC CLI failed'
    console.error(`erpc: ${message}`)
    Deno.exit(1)
  }
}

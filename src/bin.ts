import { runCli } from './cli'

runCli(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code
  },
  (error: unknown) => {
    const message = error instanceof Error ? error.message : 'ERPC CLI failed'
    console.error(message)
    process.exitCode = 1
  },
)

import { CLI_VERSION } from '../src/version.ts'

const tag = Deno.args[0]
if (!tag) throw new Error('Usage: deno run scripts/verify-release.ts vX.Y.Z')

const configuration = JSON.parse(await Deno.readTextFile('deno.json')) as {
  version?: unknown
}
if (configuration.version !== CLI_VERSION) {
  throw new Error('deno.json and CLI_VERSION are not synchronized')
}
if (tag !== `v${CLI_VERSION}`) {
  throw new Error(`Release tag ${tag} does not match v${CLI_VERSION}`)
}

console.log(`Release identity verified for ${tag}.`)

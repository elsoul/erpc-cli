import { access, readFile } from 'node:fs/promises'

const packageJson = JSON.parse(
  await readFile(new URL('../package.json', import.meta.url), 'utf8'),
)

await access(new URL('../dist/bin.js', import.meta.url))
await access(new URL('../dist/index.js', import.meta.url))
await access(new URL('../dist/index.d.ts', import.meta.url))

if (packageJson.name !== '@elsoul/erpc-cli' || packageJson.private === true) {
  throw new Error('Publishable CLI package identity check failed')
}
if (packageJson.bin?.erpc !== './dist/bin.js') {
  throw new Error('CLI binary entry point check failed')
}

const cli = await import('../dist/index.js')
if (
  typeof cli.runCli !== 'function' ||
  typeof cli.DeviceAuthClient !== 'function' ||
  typeof cli.CloudApiClient !== 'function' ||
  cli.CLI_VERSION !== packageJson.version ||
  typeof cli.initializeApp !== 'function' ||
  typeof cli.readErpcConfig !== 'function' ||
  typeof cli.findErpcManifest !== 'function' ||
  typeof cli.buildForDeployment !== 'function' ||
  typeof cli.deployOverSsh !== 'function'
) {
  throw new Error('CLI ESM export check failed')
}

console.log('CLI package entry points verified.')

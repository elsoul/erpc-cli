import { readFile } from 'node:fs/promises'

const tag = process.argv[2]
if (!tag) throw new Error('A release tag is required')

const packageJson = JSON.parse(
  await readFile(new URL('../package.json', import.meta.url), 'utf8'),
)
const expectedTag = `v${packageJson.version}`
if (tag !== expectedTag) {
  throw new Error(`Release tag ${tag} must match package version ${expectedTag}`)
}

if (packageJson.name !== '@elsoul/erpc-cli') {
  throw new Error('Unexpected npm package name')
}
if (packageJson.publishConfig?.access !== 'public') {
  throw new Error('The npm package must publish with public access')
}
if (packageJson.publishConfig?.registry !== 'https://registry.npmjs.org/') {
  throw new Error('Unexpected npm registry')
}
if (
  packageJson.repository?.url !==
  'git+https://github.com/elsoul/erpc-cli.git'
) {
  throw new Error('The repository URL must match the public GitHub repository')
}

const packageUrl =
  'https://registry.npmjs.org/' + encodeURIComponent(packageJson.name)
const response = await fetch(packageUrl, {
  headers: { accept: 'application/vnd.npm.install-v1+json' },
  signal: AbortSignal.timeout(10_000),
})

if (response.ok) {
  const metadata = await response.json()
  if (Object.hasOwn(metadata.versions ?? {}, packageJson.version)) {
    throw new Error(
      `${packageJson.name}@${packageJson.version} is already published`,
    )
  }
} else if (response.status !== 404) {
  throw new Error(`Unable to verify npm availability: HTTP ${response.status}`)
}

console.log(`${packageJson.name}@${packageJson.version} is ready for ${tag}.`)

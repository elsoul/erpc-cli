import { assert, assertEquals } from '@std/assert'
import { describe, it } from './testing.ts'
import {
  resolveExpectedSha256,
  resolveTemplateRegistryEntry,
  TEMPLATE_REGISTRY,
} from '../src/app/template-registry.ts'
import {
  isValidSha256Hex,
  isValidTemplateName,
  isValidTemplateTag,
} from '../src/app/template-ref.ts'
import { templateAssetUrl } from '../src/app/template-fetch.ts'

describe('TEMPLATE_REGISTRY', () => {
  it('names valid templates and pins valid tags to lowercase sha256 hex', () => {
    const names = Object.keys(TEMPLATE_REGISTRY)
    assert(names.length > 0)
    for (const [name, entry] of Object.entries(TEMPLATE_REGISTRY)) {
      assert(isValidTemplateName(name), name)
      for (const [tag, sha256] of Object.entries(entry.pins)) {
        assert(isValidTemplateTag(tag), `${name}@${tag}`)
        assert(isValidSha256Hex(sha256), `${name}@${tag}: ${sha256}`)
      }
    }
  })

  it('resolves stablecoin-manager@v0.1.0 to its pinned release asset', () => {
    const entry = resolveTemplateRegistryEntry(
      TEMPLATE_REGISTRY,
      'stablecoin-manager',
    )
    assertEquals(entry.source, {
      owner: 'elsoul',
      repo: 'stablecoinmanager',
      asset: 'erpc-template.tar.gz',
    })
    assertEquals(resolveExpectedSha256(entry, 'v0.1.0', undefined), {
      pinned: true,
      sha256:
        '36193691b085efe06312fafee106cf33a12d7283eca1ef4817114ee5167ab49e',
    })
    assertEquals(
      templateAssetUrl(entry.source, 'v0.1.0').href,
      'https://github.com/elsoul/stablecoinmanager/releases/download/v0.1.0/erpc-template.tar.gz',
    )
  })
})

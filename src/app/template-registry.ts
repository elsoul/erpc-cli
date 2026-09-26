// CLI-bundled template registry.

export interface TemplateSource {
  readonly asset: string
  readonly owner: string
  readonly repo: string
}

export interface TemplateRegistryEntry {
  /** tag -> sha256 (lowercase hex). A pinned tag may not be overridden by --sha256. */
  readonly pins: Readonly<Record<string, string>>
  readonly source: TemplateSource
}

export type TemplateRegistry = Readonly<Record<string, TemplateRegistryEntry>>

/**
 * The CLI-bundled name -> source/pin table. A name resolves only to the
 * repository listed here. A pinned tag's release asset must match its sha256;
 * a tag with no `pins` entry needs an explicit `--sha256`. Tests inject a
 * registry through `CliDependencies.templateRegistry` instead of relying on
 * this table.
 */
export const TEMPLATE_REGISTRY: TemplateRegistry = {
  'stablecoin-manager': {
    source: {
      owner: 'elsoul',
      repo: 'stablecoinmanager',
      asset: 'erpc-template.tar.gz',
    },
    pins: {
      'v0.1.0':
        '36193691b085efe06312fafee106cf33a12d7283eca1ef4817114ee5167ab49e',
    },
  },
}

export const resolveTemplateRegistryEntry = (
  registry: TemplateRegistry,
  name: string,
): TemplateRegistryEntry => {
  // `Object.hasOwn` (not bracket access) so a template named e.g.
  // "constructor" can't resolve through the prototype chain.
  const entry = Object.hasOwn(registry, name) ? registry[name] : undefined
  if (!entry) {
    const known = Object.keys(registry)
    throw new Error(
      known.length === 0
        ? `Unknown template: ${name} (no templates are registered in this CLI release)`
        : `Unknown template: ${name} (known templates: ${known.join(', ')})`,
    )
  }
  return entry
}

/**
 * Resolves the sha256 an archive must match for `name@tag`.
 *
 * - A pinned tag always uses the bundled sha256. An explicit `--sha256` that
 *   disagrees with the pin is rejected (pins may not be overridden).
 * - An unpinned tag requires an explicit `--sha256`.
 */
export const resolveExpectedSha256 = (
  entry: TemplateRegistryEntry,
  tag: string,
  explicitSha256: string | undefined,
): { readonly pinned: boolean; readonly sha256: string } => {
  const pinned = Object.hasOwn(entry.pins, tag) ? entry.pins[tag] : undefined
  if (pinned !== undefined) {
    if (explicitSha256 !== undefined && explicitSha256 !== pinned) {
      throw new Error(
        `--sha256 does not match the pinned checksum for this template and tag; omit --sha256 to use the pinned value`,
      )
    }
    return { pinned: true, sha256: pinned }
  }
  if (explicitSha256 === undefined) {
    throw new Error(
      `--sha256 <hex64> is required: this template tag is not pinned by this CLI release`,
    )
  }
  return { pinned: false, sha256: explicitSha256 }
}

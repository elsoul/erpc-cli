// Template ref parsing and validation.

export const TEMPLATE_NAME_PATTERN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/
export const TEMPLATE_TAG_PATTERN = /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/
export const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/

export interface TemplateRef {
  readonly name: string
  readonly tag: string
}

export const isValidTemplateName = (value: string): boolean =>
  TEMPLATE_NAME_PATTERN.test(value)

export const isValidTemplateTag = (value: string): boolean =>
  TEMPLATE_TAG_PATTERN.test(value)

export const isValidSha256Hex = (value: string): boolean =>
  SHA256_HEX_PATTERN.test(value)

/**
 * Parses a `--template <name>@<tag>` value into its name and tag parts.
 * Throws when either part fails its grammar.
 */
export const parseTemplateRef = (value: string): TemplateRef => {
  const at = value.indexOf('@')
  if (at <= 0 || at === value.length - 1) {
    throw new Error(
      '--template must be in the form <name>@<tag>, for example stablecoin-manager@v0.1.0',
    )
  }
  const name = value.slice(0, at)
  const tag = value.slice(at + 1)
  if (!isValidTemplateName(name)) {
    throw new Error(
      `Invalid template name: ${name} (must match ${TEMPLATE_NAME_PATTERN})`,
    )
  }
  if (!isValidTemplateTag(tag)) {
    throw new Error(
      `Invalid template tag: ${tag} (must match ${TEMPLATE_TAG_PATTERN}, for example v0.1.0)`,
    )
  }
  return { name, tag }
}

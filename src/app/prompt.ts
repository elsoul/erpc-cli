import type { AppRuntime } from './templates.ts'
import type { TemplateRegistry } from './template-registry.ts'

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

export type TemplateOrRuntimeChoice =
  | { readonly kind: 'runtime'; readonly runtime: AppRuntime }
  | { readonly kind: 'template'; readonly name: string }

/**
 * The `erpc app init` menu shown when neither `--runtime` nor `--template`
 * is given interactively. Choosing 1 or 2 produces the exact same result as
 * `promptForRuntime`, which this function leaves untouched.
 */
export const promptForTemplateOrRuntime = async (
  registry: TemplateRegistry,
): Promise<TemplateOrRuntimeChoice> => {
  if (!Deno.stdin.isTerminal() || !Deno.stdout.isTerminal()) {
    throw new Error(
      'Use --runtime node|deno or --template <name>@<tag> in non-interactive mode',
    )
  }
  const templateNames = Object.keys(registry).sort()
  const menu = [
    'Choose a starting point:',
    '  1. Node.js with pnpm',
    '  2. Deno',
    ...templateNames.map((name, index) => `  ${index + 3}. ${name} (template)`),
  ].join('\n')
  const answer = globalThis.prompt(`${menu}\nChoice [1]:`) ?? ''
  const normalized = answer.trim().toLowerCase()
  if (!normalized || normalized === '1' || normalized === 'node') {
    return { kind: 'runtime', runtime: 'node' }
  }
  if (normalized === '2' || normalized === 'deno') {
    return { kind: 'runtime', runtime: 'deno' }
  }
  const index = Number.parseInt(normalized, 10)
  if (
    Number.isInteger(index) && index >= 3 && index - 3 < templateNames.length
  ) {
    return { kind: 'template', name: templateNames[index - 3]! }
  }
  const byName = templateNames.find((name) => name.toLowerCase() === normalized)
  if (byName !== undefined) return { kind: 'template', name: byName }
  throw new Error('Choice must be 1, 2, or a listed template name or number')
}

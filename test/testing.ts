// deno-lint-ignore-file no-explicit-any
import {
  assert,
  assertEquals,
  assertInstanceOf,
  assertMatch,
  assertStrictEquals,
  assertThrows,
} from '@std/assert'

type TestBody = () => void | Promise<void>
type AnyFunction = (...args: any[]) => any

const suites: string[] = []
const cleanup: Array<() => void | Promise<void>> = []

export const afterEach = (operation: () => void | Promise<void>): void => {
  cleanup.push(operation)
}

export const describe = (name: string, body: () => void): void => {
  suites.push(name)
  try {
    body()
  } finally {
    suites.pop()
  }
}

const register = (name: string, body: TestBody): void => {
  const qualified = [...suites, name].join(' > ')
  Deno.test(qualified, async () => {
    try {
      await body()
    } finally {
      for (const operation of [...cleanup].reverse()) await operation()
    }
  })
}

export const it = Object.assign(register, {
  each:
    (rows: readonly (readonly unknown[])[]) =>
    (name: string, body: (...values: any[]) => void | Promise<void>): void => {
      rows.forEach((row, index) => {
        const rendered = row.reduce<string>(
          (value, item) => value.replace('%s', String(item)),
          name,
        )
        register(`${rendered} (${index + 1})`, () => body(...row))
      })
    },
})

const includes = (actual: unknown, expected: unknown): boolean =>
  typeof actual === 'string'
    ? actual.includes(String(expected))
    : Array.isArray(actual) && actual.includes(expected)

const partialMatches = (actual: unknown, expected: unknown): boolean => {
  if (expected === null || typeof expected !== 'object') {
    return Object.is(actual, expected)
  }
  if (actual === null || typeof actual !== 'object') return false
  return Object.entries(expected).every(([key, value]) =>
    partialMatches((actual as Record<string, unknown>)[key], value)
  )
}

const messageOf = (value: unknown): string =>
  value instanceof Error ? value.message : String(value)

const apply = (negated: boolean, assertion: () => void): void => {
  if (!negated) return assertion()
  let failed = false
  try {
    assertion()
  } catch {
    failed = true
  }
  assert(failed, 'Expected the assertion not to match')
}

const matchers = (actual: unknown, negated = false) => ({
  toBe(expected: unknown) {
    apply(negated, () => assertStrictEquals(actual, expected))
  },
  toBeDefined() {
    apply(negated, () => assert(actual !== undefined))
  },
  toBeInstanceOf(expected: abstract new (...args: any[]) => any) {
    apply(negated, () => assertInstanceOf(actual, expected))
  },
  toBeNull() {
    apply(negated, () => assertStrictEquals(actual, null))
  },
  toContain(expected: unknown) {
    apply(negated, () => assert(includes(actual, expected)))
  },
  toEqual(expected: unknown) {
    apply(negated, () => assertEquals(actual, expected))
  },
  toHaveBeenCalledTimes(expected: number) {
    const calls = (actual as { mock?: { calls?: unknown[] } })?.mock?.calls
    apply(negated, () => assertStrictEquals(calls?.length, expected))
  },
  toHaveLength(expected: number) {
    const length = (actual as { length?: number })?.length
    apply(negated, () => assertStrictEquals(length, expected))
  },
  toHaveProperty(expected: string) {
    apply(
      negated,
      () =>
        assert(
          actual !== null && typeof actual === 'object' && expected in actual,
        ),
    )
  },
  toMatch(expected: RegExp) {
    apply(negated, () => assertMatch(String(actual), expected))
  },
  toMatchObject(expected: unknown) {
    apply(negated, () => assert(partialMatches(actual, expected)))
  },
  toThrow(expected?: string | RegExp) {
    assert(typeof actual === 'function')
    const error = assertThrows(actual as () => unknown)
    if (typeof expected === 'string') {
      assert(messageOf(error).includes(expected))
    } else if (expected) assertMatch(messageOf(error), expected)
  },
})

export const expect = (actual: unknown) => ({
  ...matchers(actual),
  not: matchers(actual, true),
  rejects: {
    async toThrow(expected?: string | RegExp) {
      let rejection: unknown
      try {
        await actual
      } catch (error) {
        rejection = error
      }
      assert(rejection !== undefined, 'Expected promise to reject')
      if (typeof expected === 'string') {
        assert(messageOf(rejection).includes(expected))
      } else if (expected) {
        assertMatch(messageOf(rejection), expected)
      }
    },
  },
  resolves: {
    async toBe(expected: unknown) {
      matchers(await actual).toBe(expected)
    },
    async toContain(expected: unknown) {
      matchers(await actual).toContain(expected)
    },
    async toEqual(expected: unknown) {
      matchers(await actual).toEqual(expected)
    },
    async toMatchObject(expected: unknown) {
      matchers(await actual).toMatchObject(expected)
    },
  },
})

type MockFunction<T extends AnyFunction> = T & {
  mock: { calls: Array<Parameters<T>> }
  mockResolvedValue(value: Awaited<ReturnType<T>>): MockFunction<T>
  mockResolvedValueOnce(value: Awaited<ReturnType<T>>): MockFunction<T>
}

const mockFunction = <T extends AnyFunction>(
  implementation?: T,
): MockFunction<T> => {
  const calls: Array<Parameters<T>> = []
  const resolved: Array<Awaited<ReturnType<T>>> = []
  let fallback: Awaited<ReturnType<T>> | undefined
  const callable = ((...args: Parameters<T>) => {
    calls.push(args)
    if (resolved.length > 0) return Promise.resolve(resolved.shift())
    if (fallback !== undefined) return Promise.resolve(fallback)
    return implementation?.(...args)
  }) as MockFunction<T>
  callable.mock = { calls }
  callable.mockResolvedValueOnce = (value) => {
    resolved.push(value)
    return callable
  }
  callable.mockResolvedValue = (value) => {
    fallback = value
    return callable
  }
  return callable
}

export const vi = { fn: mockFunction }

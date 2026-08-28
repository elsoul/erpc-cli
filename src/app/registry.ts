import { readdir } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import {
  type ErpcConfigOptions,
  type ErpcLocalConfig,
  readErpcConfig,
} from '../config.ts'
import { loadErpcManifest } from './manifest.ts'
import type { AppRuntime } from './templates.ts'

export interface RegisteredApplication {
  readonly config: string
  readonly name: string
  readonly root: string
  readonly runtime: AppRuntime
  readonly target: string
}

const managedConfigPaths = async (
  config: ErpcLocalConfig,
): Promise<string[]> => {
  const entries = await readdir(config.appsDirectory, { withFileTypes: true })
  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => join(config.appsDirectory, entry.name, 'erpc.toml'))
}

export const listErpcApplications = async (
  options: ErpcConfigOptions = {},
): Promise<readonly RegisteredApplication[]> => {
  const config = await readErpcConfig(options)
  const paths = new Set([
    ...await managedConfigPaths(config),
    ...config.apps.map((app) => resolve(app.config)),
  ])
  const applications: RegisteredApplication[] = []
  for (const path of paths) {
    try {
      const manifest = await loadErpcManifest(path)
      applications.push({
        config: manifest.configPath,
        name: manifest.name,
        root: manifest.projectRoot,
        runtime: manifest.app.runtime,
        target: manifest.deploy.target,
      })
    } catch (error) {
      if (config.apps.some((app) => app.config === path)) throw error
    }
  }
  return applications.sort((left, right) => left.name.localeCompare(right.name))
}

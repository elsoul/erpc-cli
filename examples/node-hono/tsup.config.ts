import { defineConfig } from 'tsup'

export default defineConfig({
  clean: true,
  entry: ['src/index.ts'],
  format: ['esm'],
  noExternal: ['@hono/node-server', 'hono'],
  outDir: 'dist',
  platform: 'node',
  sourcemap: true,
  target: 'node20',
})

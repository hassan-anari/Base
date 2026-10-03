import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

// Build config for the standalone API Simulator SPA (frontend/simulator).
// Output goes to ../frontend/dist_simulator so Django can serve it at /simulator/.
export default defineConfig({
  root: resolve(__dirname, 'simulator'),
  plugins: [vue()],
  base: '/simulator/',
  build: {
    outDir: resolve(__dirname, '../backend/simulator_dist'),
    emptyOutDir: true,
    assetsDir: 'assets',
    manifest: false,
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, 'simulator/src'),
    },
  },
})
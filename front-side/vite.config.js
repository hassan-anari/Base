import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Build output is served by Django at `/` so the whole product runs on one port.
// When building for the Django (gunicorn + whitenoise) origin, assets are
// served from STATIC_ROOT under the "/static/" prefix, so Vite must emit
// absolute "/static/" references. The Vite dev server (npm run dev) keeps
// base "/" and proxies /api -> :8000.
const PROD_BUILD = process.env.BUILD_TARGET === 'django'
const base = PROD_BUILD ? '/static/' : '/'

export default defineConfig({
  plugins: [vue()],
  base,
  server: { port: 5173, proxy: { '/api': 'http://localhost:8000' } },
  build: {
    outDir: '../backend-side/frontend_dist',
    emptyOutDir: true,
    // Keep asset filenames stable for whitenoise immutable caching.
    assetsDir: 'assets',
  },
})

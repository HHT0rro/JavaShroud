import { resolve } from 'node:path'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  base: './',
  build: {
    outDir: resolve(__dirname, '../../build/frontend/file-preview'),
    emptyOutDir: true,
    target: 'es2022',
    cssTarget: 'chrome109',
    sourcemap: false,
    minify: 'oxc',
    reportCompressedSize: false,
    modulePreload: {
      polyfill: false,
    },
    rollupOptions: {
      input: { index: resolve(__dirname, 'debug.html') },
      output: {
        manualChunks(id: string): string | undefined {
          if (id.includes('node_modules/vue') || id.includes('node_modules/naive-ui')) {
            return 'vendor'
          }
          return undefined
        },
      },
    },
  },
})

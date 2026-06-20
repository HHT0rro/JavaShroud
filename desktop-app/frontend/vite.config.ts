import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: 'dist',
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
      output: {
        manualChunks(id: string): string | undefined {
          if (id.includes('node_modules/xterm')) {
            return 'terminal'
          }
          if (id.includes('node_modules/vue') || id.includes('node_modules/naive-ui')) {
            return 'vendor'
          }
          return undefined
        },
      },
    },
  },
})

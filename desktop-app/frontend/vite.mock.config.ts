import { resolve } from 'node:path'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5174,
    strictPort: true,
    open: '/debug.html',
  },
  build: {
    rollupOptions: {
      input: { debug: resolve(__dirname, 'debug.html') },
    },
  },
})

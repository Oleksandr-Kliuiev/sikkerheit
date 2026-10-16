/// <reference types="vitest/config" />
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// The service serves the built portal from its wwwroot (02 «Компоненты»); in development Vite proxies the API.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../Sikkerheit.Host/wwwroot',
    emptyOutDir: true,
    sourcemap: false,
    assetsInlineLimit: 0,
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': 'http://localhost:5080',
      '/auth': 'http://localhost:5080',
    },
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}'],
  },
});

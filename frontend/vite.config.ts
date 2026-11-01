import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: Number(process.env.PORT || 5173),
    proxy: {
      '/api': { target: process.env.PASSGUARD_API_PROXY || 'http://127.0.0.1:8000', changeOrigin: true },
      '/ready': { target: process.env.PASSGUARD_API_PROXY || 'http://127.0.0.1:8000' },
    },
  },
  build: { sourcemap: false },
});

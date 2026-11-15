import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// CYBERGUARD_BACKEND_URL and CYBERGUARD_FRONTEND_PORT allow running a second,
// isolated instance (for example against the test database). The frontend
// origin must match APP_ORIGIN of the backend it talks to.
const backend = process.env.CYBERGUARD_BACKEND_URL || 'http://127.0.0.1:8080';
const port = Number(process.env.CYBERGUARD_FRONTEND_PORT) || 3000;

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port,
    strictPort: true,
    // Analysis requests wait for external providers for up to three minutes.
    proxy: { '/api': { target: backend, changeOrigin: false, timeout: 200000, proxyTimeout: 200000 } },
  },
  test: { environment: 'jsdom', setupFiles: './src/test/setup.js' },
});

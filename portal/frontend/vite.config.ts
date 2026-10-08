import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react()],
  server: {
    // Bind all interfaces (not just loopback) so the dashboard is reachable from other devices on
    // the LAN, not only from this host - the backend proxy target below stays 127.0.0.1 regardless,
    // since that connection is made server-side by this same Vite process, never by the browser.
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': 'http://127.0.0.1:8811',
      '/ws': {
        target: 'ws://127.0.0.1:8811',
        ws: true,
      },
    },
  },
})

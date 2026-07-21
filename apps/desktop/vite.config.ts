import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  build: {
    // Tauri's CSP intentionally blocks data: images. Keep SVG tool/provider
    // logos as regular bundled assets so they are loaded from 'self'.
    assetsInlineLimit: 0,
  },
  server: {
    port: 1420,
    strictPort: true,
  },
});

/// <reference types="vitest" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

/**
 * Dos cosas de esta configuracion no son cosmeticas:
 *
 * 1. `modulePreload.polyfill: false`. Con el valor por omision, Vite inyecta un
 *    script INLINE en index.html, y la CSP del runtime es `script-src 'self'`
 *    sin `unsafe-inline`: el navegador lo bloquearia. Se desactiva aqui en vez
 *    de debilitar la politica. Lo que se pierde es la precarga de modulos en
 *    navegadores sin `modulepreload`, no funcionalidad.
 *
 * 2. El proxy de `/api` SOLO existe en desarrollo (`vite dev`), y apunta al
 *    nombre de servicio de la red de Docker, porque el perfil de desarrollo
 *    tambien es un contenedor dentro de `network-service`. En el runtime de
 *    `make all` no hay Vite: el mismo prefijo lo reenvia Nginx.
 */
export default defineConfig({
  base: "/",
  plugins: [react()],
  build: {
    outDir: "dist",
    assetsDir: "assets",
    sourcemap: false,
    modulePreload: { polyfill: false },
  },
  server: {
    host: true,
    port: 5173,
    strictPort: true,
    proxy: {
      "/api/user_mgmt/v1": {
        target: "http://user-mgmt-service:8000",
        changeOrigin: false,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: false,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    restoreMocks: true,
    clearMocks: true,
    // El doble HTTP sustituye `fetch` con stubGlobal: sin esto, el sustituto
    // sobreviviria de una prueba a la siguiente.
    unstubGlobals: true,
  },
});

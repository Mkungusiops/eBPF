import react from "@vitejs/plugin-react";
import { resolve } from "node:path";
import { defineConfig } from "vite";
import { VitePWA } from "vite-plugin-pwa";

const root = __dirname;

export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      // The build emits sw.js + manifest.webmanifest at the dist root; the Go
      // engine serves them (see engine/internal/api/web_assets.go). We register
      // the worker ourselves in src/app/render.tsx, so disable auto-injection.
      registerType: "autoUpdate",
      injectRegister: null,
      devOptions: {
        // Keep the manifest visible during local browser tests without
        // registering a development service worker.
        enabled: true
      },
      manifest: {
        id: "/",
        name: "eBPF Security Console",
        short_name: "eBPF SOC",
        description: "Realtime eBPF threat observability and response console",
        // A manifest carries ONE value for each of these and cannot express a
        // media query, unlike the <meta name="theme-color"> pair in every entry
        // HTML, which does have light and dark variants. That meta overrides
        // this for browser UI once the page paints, so these two govern only
        // the install splash and the window chrome before first paint.
        //
        // They stay dark deliberately: the app's initial theme follows the OS
        // (see lib/theme.ts) and dark is the product's primary presentation, so
        // this is the least-wrong single value. The residual is a light-mode
        // operator seeing a dark splash for one frame on an installed app —
        // a platform limitation, not something a different constant fixes.
        theme_color: "#0a0f1c",
        background_color: "#0a0f1c",
        display: "standalone",
        start_url: "/",
        scope: "/",
        orientation: "any",
        categories: ["security", "productivity", "utilities"],
        prefer_related_applications: false,
        shortcuts: [
          { name: "SOC dashboard", short_name: "SOC", url: "/", icons: [{ src: "/pwa-192x192.png?v=3", sizes: "192x192", type: "image/png" }] },
          { name: "Choke Gateway", short_name: "Choke", url: "/choke", icons: [{ src: "/pwa-192x192.png?v=3", sizes: "192x192", type: "image/png" }] },
          { name: "Devices", short_name: "Devices", url: "/devices", icons: [{ src: "/pwa-192x192.png?v=3", sizes: "192x192", type: "image/png" }] }
        ],
        icons: [
          { src: "/pwa-192x192.png?v=3", sizes: "192x192", type: "image/png", purpose: "any" },
          { src: "/pwa-512x512.png?v=3", sizes: "512x512", type: "image/png", purpose: "any" },
          { src: "/pwa-maskable-512x512.png?v=3", sizes: "512x512", type: "image/png", purpose: "maskable" }
        ]
      },
      workbox: {
        // Self-contained worker so the engine only has to serve /sw.js.
        inlineWorkboxRuntime: true,
        clientsClaim: true,
        skipWaiting: true,
        // Drop precaches from older builds (e.g. the HTML-precaching worker
        // that 404'd on the engine's clean URLs and looped on install).
        cleanupOutdatedCaches: true,
        // CRITICAL: never precache HTML. The engine serves pages at clean,
        // auth-gated URLs (/choke, not /choke.html); precaching the shells
        // both 404s on install AND lets the worker answer the "/" navigation
        // from cache, bypassing the login redirect. Precache only immutable,
        // content-hashed static assets and let every navigation hit the
        // network so server-side auth always runs.
        navigateFallback: null,
        globPatterns: ["**/*.{js,css,svg,png,ico,woff2}"],
        // Never let the worker touch the API — this is an authenticated,
        // realtime security console and responses must not sit on disk.
        navigateFallbackDenylist: [/^\/api/],
        runtimeCaching: []
      }
    })
  ],
  server: {
    port: 5173,
    strictPort: false,
    proxy: {
      "/api": {
        target: process.env.EBPF_ENGINE_URL ?? "http://127.0.0.1:8080",
        changeOrigin: true
      },
      "/favicon.svg": process.env.EBPF_ENGINE_URL ?? "http://127.0.0.1:8080",
      "/favicon.ico": process.env.EBPF_ENGINE_URL ?? "http://127.0.0.1:8080",
      "/favicon-light.svg": process.env.EBPF_ENGINE_URL ?? "http://127.0.0.1:8080"
    }
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: true,
    rollupOptions: {
      input: {
        soc: resolve(root, "index.html"),
        choke: resolve(root, "choke.html"),
        devices: resolve(root, "devices.html"),
        fleet: resolve(root, "fleet.html"),
        login: resolve(root, "login.html")
      }
    }
  }
});

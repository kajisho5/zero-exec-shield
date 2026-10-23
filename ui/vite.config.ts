import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// The version in the header is embedded from the version in ui/package.json (so a hand-written string cannot drift from CHANGELOG and zes-scan.sh)
const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as { version: string };
const src = (p: string) => fileURLToPath(new URL(`./src/${p}`, import.meta.url));

// The build output goes to ui/dist, and scripts/inline-build.mjs inlines the JS/CSS into the single file ../index.html
// and writes the CSP (SHA-256 of script/style). Zero external fetches at runtime.
export default defineConfig({
  base: './',
  define: { __ZES_UI_VERSION__: JSON.stringify(pkg.version) },
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: [
      { find: /^@\//, replacement: src('') },
      // react-remove-scroll, used by the Radix Dialog / Popover / Menu, injects <style> at runtime and is blocked by the hash-based
      // CSP. It is replaced with a compatible module that locks via CSSOM (design doc §4.2).
      { find: /^react-remove-scroll$/, replacement: src('lib/remove-scroll-csp.tsx') },
    ],
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    modulePreload: false,
    cssCodeSplit: false,
    assetsInlineLimit: Number.MAX_SAFE_INTEGER,
    sourcemap: false,
    rolldownOptions: {
      output: { codeSplitting: false, entryFileNames: 'app.js', assetFileNames: 'app[extname]' },
    },
  },
});

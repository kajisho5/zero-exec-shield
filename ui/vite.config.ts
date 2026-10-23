import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// ヘッダーの版は ui/package.json の version から埋め込む（手で書いた文字列と CHANGELOG・zes-scan.sh がずれないように）
const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as { version: string };
const src = (p: string) => fileURLToPath(new URL(`./src/${p}`, import.meta.url));

// ビルド成果物は ui/dist に出し、scripts/inline-build.mjs が JS/CSS を 1 ファイルの ../index.html に
// インライン化して CSP（script/style の SHA-256）を書き込む。ランタイムでの外部取得はゼロ。
export default defineConfig({
  base: './',
  define: { __ZES_UI_VERSION__: JSON.stringify(pkg.version) },
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: [
      { find: /^@\//, replacement: src('') },
      // Radix の Dialog / Popover / Menu が使う react-remove-scroll は実行時に <style> を差し込み、ハッシュ方式の CSP に
      // ブロックされる。CSSOM でロックする互換モジュールに差し替える（設計書 §4.2）。
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

import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// ビルド成果物は ui/dist に出し、scripts/inline-build.mjs が JS/CSS を 1 ファイルの ../index.html に
// インライン化して CSP（script/style の SHA-256）を書き込む。ランタイムでの外部取得はゼロ。
export default defineConfig({
  base: './',
  plugins: [react(), tailwindcss()],
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

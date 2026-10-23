// vite build の成果物（ui/dist）を 1 ファイルの ../index.html にまとめ、CSP をスクリプト / スタイルの SHA-256 で書き込む。
// ランタイムで外部リソースを一切取得しない（CDN 禁止・file:// 動作）。
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const dist = here('../dist/');
let html = readFileSync(dist + 'index.html', 'utf8');
const js = readFileSync(dist + 'app.js', 'utf8');
const css = readFileSync(dist + 'app.css', 'utf8');
// ファビコンは brand/ の生成物を data: URI で埋め込む（CSP img-src data: の範囲内。外部取得なし）
const icon = readFileSync(here('../../brand/web/favicon-64.png')).toString('base64');

// </script> / </style> の終端を本文中に含まないことを確認（含むとインライン化で HTML が壊れる）
if (/<\/script/i.test(js)) throw new Error('app.js に </script が含まれるためインライン化できません');
if (/<\/style/i.test(css)) throw new Error('app.css に </style が含まれるためインライン化できません');

// 実行時に <style> を差し込むライブラリが紛れ込んでいないこと（ハッシュ方式の CSP でブロックされる。設計書 §4.2、R-1）。
// react-remove-scroll は vite.config.ts の alias で CSSOM 版に差し替えている。差し替えが外れると次の文字列が入る。
for (const marker of ['block-interactivity-', 'with-scroll-bars-hidden', 'data-sonner-toaster', 'data-radix-scroll-area-viewport', 'data-radix-select-viewport']) {
  if (js.includes(marker)) throw new Error(`app.js に実行時に <style> を差し込むライブラリの痕跡があります: ${marker}`);
}

const scriptTag = /<script type="module" crossorigin src="\.\/app\.js"><\/script>/;
const styleTag = /<link rel="stylesheet" crossorigin href="\.\/app\.css">/;
if (!scriptTag.test(html) || !styleTag.test(html)) throw new Error('dist/index.html の script / link タグが想定と異なります');

const b64 = (s) => createHash('sha256').update(s, 'utf8').digest('base64');
const csp = [
  "default-src 'none'",
  `script-src 'sha256-${b64(js)}'`,
  `style-src 'sha256-${b64(css)}'`,
  'img-src data:',
  "font-src 'none'",
  "connect-src 'none'",
  "frame-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

// 置換文字列中の $ を特殊扱いさせないため関数で置換する
html = html
  .replace(scriptTag, () => '')
  .replace(styleTag, () => `<style>${css}</style>`)
  .replace('<!--ZES-CSP-->', () => `<meta http-equiv="Content-Security-Policy" content="${csp}" />`)
  .replace('<!--ZES-ICON-->', () => `<link rel="icon" type="image/png" sizes="64x64" href="data:image/png;base64,${icon}" />`)
  .replace('</body>', () => `<script type="module">${js}</script>\n  </body>`);

// 成果物の <style> はビルド時の CSS の 1 つだけ（CSP の style-src はそのハッシュ 1 つだけを許可する）
if ((html.match(/<style[\s>]/g) ?? []).length !== 1) throw new Error('成果物の <style> が 1 つではありません');

const banner = '<!-- Zero-Exec Shield v5.2 Web Scanner UI。ui/ から生成（cd ui && npm ci && npm run build）。直接編集しないこと。 -->\n';
writeFileSync(here('../../index.html'), banner + html);
console.log(`index.html: ${(Buffer.byteLength(banner + html) / 1024).toFixed(0)} KiB（CSP: script/style SHA-256）`);

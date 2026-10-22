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

// </script> / </style> の終端を本文中に含まないことを確認（含むとインライン化で HTML が壊れる）
if (/<\/script/i.test(js)) throw new Error('app.js に </script が含まれるためインライン化できません');
if (/<\/style/i.test(css)) throw new Error('app.css に </style が含まれるためインライン化できません');

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
  .replace('</body>', () => `<script type="module">${js}</script>\n  </body>`);

const banner = '<!-- Zero-Exec Shield v5.2 Web Scanner UI。ui/ から生成（cd ui && npm ci && npm run build）。直接編集しないこと。 -->\n';
writeFileSync(here('../../index.html'), banner + html);
console.log(`index.html: ${(Buffer.byteLength(banner + html) / 1024).toFixed(0)} KiB（CSP: script/style SHA-256）`);

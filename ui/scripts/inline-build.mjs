// Bundles the vite build output (ui/dist) into the single file ../index.html and writes the CSP with the SHA-256 of the script / style.
// Never fetches any external resource at runtime (no CDN, works on file://).
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const dist = here('../dist/');
let html = readFileSync(dist + 'index.html', 'utf8');
const js = readFileSync(dist + 'app.js', 'utf8');
const css = readFileSync(dist + 'app.css', 'utf8');
// The favicon embeds the generated file from brand/ as a data: URI (within CSP img-src data:; no external fetch)
const icon = readFileSync(here('../../brand/web/favicon-64.png')).toString('base64');

// Check that the body contains no </script> / </style> terminator (if it did, inlining would break the HTML)
if (/<\/script/i.test(js)) throw new Error('app.js に </script が含まれるためインライン化できません');
if (/<\/style/i.test(css)) throw new Error('app.css に </style が含まれるためインライン化できません');

// No library that injects <style> at runtime has slipped in (it would be blocked by the hash-based CSP. design doc §4.2, R-1).
// react-remove-scroll is replaced with the CSSOM version by the alias in vite.config.ts. If the replacement is lost, the following strings get in.
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

// Replace with a function so that $ in the replacement string is not treated specially
html = html
  .replace(scriptTag, () => '')
  .replace(styleTag, () => `<style>${css}</style>`)
  .replace('<!--ZES-CSP-->', () => `<meta http-equiv="Content-Security-Policy" content="${csp}" />`)
  .replace('<!--ZES-ICON-->', () => `<link rel="icon" type="image/png" sizes="64x64" href="data:image/png;base64,${icon}" />`)
  .replace('</body>', () => `<script type="module">${js}</script>\n  </body>`);

// The output has exactly one <style>, the CSS from the build (the CSP style-src allows only that one hash)
if ((html.match(/<style[\s>]/g) ?? []).length !== 1) throw new Error('成果物の <style> が 1 つではありません');

const banner = '<!-- Zero-Exec Shield v5.2 Web Scanner UI。ui/ から生成（cd ui && npm ci && npm run build）。直接編集しないこと。 -->\n';
writeFileSync(here('../../index.html'), banner + html);
console.log(`index.html: ${(Buffer.byteLength(banner + html) / 1024).toFixed(0)} KiB（CSP: script/style SHA-256）`);

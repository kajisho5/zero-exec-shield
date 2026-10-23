// Static check: the output index.html has no external network API and no external URL, and the source has no execution APIs.
// If even one is found, exit code 1 (the build fails).
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const target = process.argv[2] ?? '../index.html';
const original = readFileSync(target, 'utf8');
let html = original;
const problems = [];

// The CSP and the loading tags are checked on the HTML before processing
const csp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(original)?.[1] ?? '';
for (const d of ["default-src 'none'", "connect-src 'none'", "script-src 'sha256-", "style-src 'sha256-"]) {
  if (!csp.includes(d)) problems.push(`CSP に ${d} がありません`);
}
if (/unsafe-inline|unsafe-eval/.test(csp)) problems.push('CSP に unsafe-inline / unsafe-eval が含まれます');
for (const re of [/<script[^>]+src=/i, /<link\b[^>]*?\bhref\s*=\s*(?!["']?data:)/i, /<img\b[^>]*?\bsrc\s*=\s*(?!["']?data:)/i, /<iframe/i]) {
  if (re.test(original)) problems.push(`成果物に外部読み込みタグ: ${re}`);
}

// The strings of rules/ioc.json (detection patterns, IoCs, descriptions) are bundled as data. They are not API calls, so
// both the raw form and the form escaped as a JS string are removed before scanning (longest first).
const ioc = JSON.parse(readFileSync(fileURLToPath(new URL('../../rules/ioc.json', import.meta.url)), 'utf8'));
const strs = [];
const collect = (v) => (typeof v === 'string' ? strs.push(v) : v && typeof v === 'object' ? Object.entries(v).forEach(([k, x]) => { strs.push(k); collect(x); }) : null);
collect(ioc);
for (const s of [...new Set(strs)].filter((x) => x.length >= 6).sort((a, b) => b.length - a.length)) {
  for (const form of [s, JSON.stringify(s).slice(1, -1)]) html = html.split(form).join('');
}

// 1) External network APIs (even appearing as a string is forbidden; this also confirms dependencies such as React do not include them)
for (const re of [/\bfetch\s*\(/, /XMLHttpRequest/, /new\s+WebSocket/, /EventSource/, /sendBeacon/, /importScripts/, /\bimport\s*\(\s*["'`]https?:/]) {
  if (re.test(html)) problems.push(`成果物に通信 API: ${re}`);
}
// 2) External URLs (allowlist: the SVG namespace, URL strings in React production error messages, references in the spec and IoC descriptions)
// None of them are strings used for network access (namespace URIs, React production build error messages, license notices)
const ALLOW = [
  /^http:\/\/www\.w3\.org\/(2000\/svg|1999\/xhtml|1998\/Math\/MathML|1999\/xlink|XML\/1998\/(namespace|space))$/,
  /^https:\/\/reactjs\.org\/(docs\/)?error-decoder\.html\?invariant=$/,
  // React 19 production error messages ("Minified React error #N; visit https://react.dev/errors/N"). Only concatenated as a string, no network access
  /^https:\/\/react\.dev\/errors\/$/,
  /^https:\/\/tailwindcss\.com$/,
];
for (const m of html.matchAll(/https?:\/\/[^\s"'`<>)\\*]+/g)) {
  if (!ALLOW.some((re) => re.test(m[0]))) problems.push(`成果物に外部 URL: ${m[0].slice(0, 120)}`);
}

// 3) The source (ui/src) has no execution APIs and no raw HTML writes (N-05)
const src = fileURLToPath(new URL('../src/', import.meta.url));
const walk = (d) => readdirSync(d).flatMap((n) => (statSync(join(d, n)).isDirectory() ? walk(join(d, n)) : [join(d, n)]));
for (const f of walk(src).filter((f) => /\.(ts|tsx)$/.test(f))) {
  const s = readFileSync(f, 'utf8');
  for (const re of [/\beval\s*\(/, /new\s+Function\s*\(/, /dangerouslySetInnerHTML/, /\.innerHTML\s*=/, /\bfetch\s*\(/, /XMLHttpRequest/, /WebSocket/, /setTimeout\s*\(\s*["'`]/, /new\s+Worker\s*\(/]) {
    if (re.test(s)) problems.push(`${f.slice(src.length)}: 禁止 API ${re}`);
  }
}

if (problems.length) {
  console.error('verify-no-network: NG');
  for (const p of problems) console.error('  - ' + p);
  process.exit(1);
}
console.log('verify-no-network: OK（通信 API・外部 URL・外部読み込み・実行系 API なし、CSP はハッシュ方式）');

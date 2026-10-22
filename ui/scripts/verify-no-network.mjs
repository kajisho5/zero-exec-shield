// 静的検査: 成果物 index.html に外部通信 API・外部 URL が無いこと、ソースに実行系 API が無いことを確認する。
// 一つでも見つかれば終了コード 1（ビルド失敗）。
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const target = process.argv[2] ?? '../index.html';
const original = readFileSync(target, 'utf8');
let html = original;
const problems = [];

// CSP と読み込みタグは加工前の HTML で検査する
const csp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(original)?.[1] ?? '';
for (const d of ["default-src 'none'", "connect-src 'none'", "script-src 'sha256-", "style-src 'sha256-"]) {
  if (!csp.includes(d)) problems.push(`CSP に ${d} がありません`);
}
if (/unsafe-inline|unsafe-eval/.test(csp)) problems.push('CSP に unsafe-inline / unsafe-eval が含まれます');
for (const re of [/<script[^>]+src=/i, /<link[^>]+href="(?!data:)/i, /<img[^>]+src="(?!data:)/i, /<iframe/i]) {
  if (re.test(original)) problems.push(`成果物に外部読み込みタグ: ${re}`);
}

// rules/ioc.json の文字列（検出パターン・IoC・説明文）はデータとしてバンドルされる。API 呼び出しではないため、
// 生の形と JS 文字列としてエスケープされた形の両方を取り除いてから走査する（長いものから順に）。
const ioc = JSON.parse(readFileSync(fileURLToPath(new URL('../../rules/ioc.json', import.meta.url)), 'utf8'));
const strs = [];
const collect = (v) => (typeof v === 'string' ? strs.push(v) : v && typeof v === 'object' ? Object.entries(v).forEach(([k, x]) => { strs.push(k); collect(x); }) : null);
collect(ioc);
for (const s of [...new Set(strs)].filter((x) => x.length >= 6).sort((a, b) => b.length - a.length)) {
  for (const form of [s, JSON.stringify(s).slice(1, -1)]) html = html.split(form).join('');
}

// 1) 外部通信 API（文字列としての出現も禁止。React 等の依存が含めていないことも併せて確認）
for (const re of [/\bfetch\s*\(/, /XMLHttpRequest/, /new\s+WebSocket/, /EventSource/, /sendBeacon/, /importScripts/, /\bimport\s*\(\s*["'`]https?:/]) {
  if (re.test(html)) problems.push(`成果物に通信 API: ${re}`);
}
// 2) 外部 URL（許可リスト: SVG 名前空間、React の本番エラーメッセージ中の URL 文字列、仕様・IoC 説明中の参照）
// いずれも通信には使われない文字列（名前空間 URI、React 本番ビルドのエラーメッセージ、ライセンス表記）
const ALLOW = [
  /^http:\/\/www\.w3\.org\/(2000\/svg|1999\/xhtml|1998\/Math\/MathML|1999\/xlink|XML\/1998\/(namespace|space))$/,
  /^https:\/\/reactjs\.org\/(docs\/)?error-decoder\.html\?invariant=$/,
  /^https:\/\/tailwindcss\.com$/,
];
for (const m of html.matchAll(/https?:\/\/[^\s"'`<>)\\*]+/g)) {
  if (!ALLOW.some((re) => re.test(m[0]))) problems.push(`成果物に外部 URL: ${m[0].slice(0, 120)}`);
}

// 3) ソース（ui/src）に実行系 API・HTML 直書きが無いこと（N-05）
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

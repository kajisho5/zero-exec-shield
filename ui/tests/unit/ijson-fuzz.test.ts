// The §49 I-JSON check of the UI (ijsonProblem) against the CLI's sp_ijson_problem on seeded random inputs (round-6 UI 2: an
//   empty array left its member-name set on the stack, so a valid contract read as "duplicate member name"). The inputs are
//   structured values with mutations, raw invalid UTF-8, BOMs, NUL, surrogate escapes and edge numbers; every one must give
//   the same problem on both sides. Bounded: ZES_IJFUZZ_N inputs per seed (default 1500) and ZES_IJFUZZ_SEEDS (default
//   "1,2"); a larger run (5 seeds of 5000, 0 differences) is described in the 0.5.4 changelog. Needs bash and awk (skipped
//   without them); the CLI functions are taken from ../../zes-scan.sh like tests/run-tests.sh does.
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, it } from 'vitest';
import { ijsonProblem } from '../../src/engine/skillpact';

const SCAN = fileURLToPath(new URL('../../../zes-scan.sh', import.meta.url));
const HAVE_SH = spawnSync('bash', ['-c', 'command -v awk >/dev/null'], { stdio: 'ignore' }).status === 0;
// prints "<file> TAB <problem>" for every file of the directory, with the CLI's sp_ijson_problem
const CLI = `export LC_ALL=C; eval "$(sed -n "/^ZES_AWK_LIB=/,/^'\\$/p; /^sp_ijson_problem() {/,/^}/p" "$1")"; for f in "$2"/*; do printf '%s\\t%s\\n' "\${f##*/}" "$(sp_ijson_problem "$f")"; done`;

let seed = 1;
const rnd = () => { seed |= 0; seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const pick = <T,>(a: T[]): T => a[Math.floor(rnd() * a.length)]!;
const atoms = ['{', '}', '[', ']', ':', ',', '"', '\\', 'u', 'd83d', 'de00', 'dc00', 'D800', '0', '1', '9', '-', '+', '.', 'e', 'E', '00', '9007199254740991', '9007199254740992', '9007199254740991.0', '0.9007199254740991e16', '90071992547409915e-1', '1e15', '1e16', '1e400', '1e-400', '1e0000000016', '-0', 'true', 'false', 'null', 'tru', 'nul', 'NaN', ' ', '\t', '\n', '\r', '\v', '\f', ' ', '﻿', ' ', '\u0000', '\u0001', '\u001f', '\u007f', '�', 'é', '😀', '"a"', '"a"', '"b"', '"\\u0061"', '"\\/"', '\\/', '\\"', '\\n', '\\x', 'a', '{"a":', '"a":1', '[[[[', ']]]]'];
const rawBytes = [[0xc0, 0x80], [0xed, 0xa0, 0x80], [0xef, 0xbf, 0xbd], [0xff], [0xe2, 0x82], [0xf0, 0x9f, 0x98], [0xf4, 0x90, 0x80, 0x80], [0xef, 0xbb, 0xbf], [0x80], [0xe0, 0x80, 0x80], [0xc2, 0xa0]];
function gen(): Uint8Array {
  const parts: number[] = [];
  const enc = new TextEncoder();
  const mode = rnd();
  if (mode < 0.5) {
    // structurally plausible: build a value then mutate
    const val = (d: number): string => {
      const r = rnd();
      if (d > 4 || r < 0.3) return pick(['1', '0', '-0.5e3', '"x"', '"\\u00e9"', '"\\ud83d\\ude00"', 'true', 'null', '9007199254740991', '-9007199254740992', '1.5E+2', '"a\\"b"', '""', '"\\u0000"', '"\\uDC00"']);
      if (r < 0.65) { const n = Math.floor(rnd() * 4); const ks = Array.from({ length: n }, () => `${pick(['"a"', '"b"', '"\\u0061"', '"é"', '"e\\u0301"', '"\\u00e9"', '""'])}:${val(d + 1)}`); return `{${ks.join(',')}}`; }
      return `[${Array.from({ length: Math.floor(rnd() * 4) }, () => val(d + 1)).join(',')}]`;
    };
    let s = val(0);
    if (rnd() < 0.7) s = `{"k":${s}}`;
    const b = [...enc.encode(s)];
    const muts = Math.floor(rnd() * 3);
    for (let m = 0; m < muts; m++) {
      const pos = Math.floor(rnd() * (b.length + 1));
      const r = rnd();
      if (r < 0.4) b.splice(pos, 0, ...enc.encode(pick(atoms)));
      else if (r < 0.6) b.splice(pos, 1);
      else b.splice(pos, 0, ...pick(rawBytes));
    }
    if (rnd() < 0.1) b.unshift(0xef, 0xbb, 0xbf);
    return new Uint8Array(b);
  }
  const n = 1 + Math.floor(rnd() * 12);
  for (let k = 0; k < n; k++) { if (rnd() < 0.15) parts.push(...pick(rawBytes)); else parts.push(...enc.encode(pick(atoms))); }
  return new Uint8Array(parts);
}

it.skipIf(!HAVE_SH)('ijsonProblem gives the problem sp_ijson_problem gives (seeded fuzz)', () => {
  const N = Number(process.env.ZES_IJFUZZ_N ?? 1500);
  const seeds = (process.env.ZES_IJFUZZ_SEEDS ?? '1,2').split(',').map(Number);
  const diffs: string[] = [];
  let total = 0;
  for (const sd of seeds) {
    seed = sd;
    const dir = mkdtempSync(join(tmpdir(), 'zes-ijfuzz-'));
    try {
      const cases: Uint8Array[] = [];
      for (let k = 0; k < N; k++) { const b = gen(); cases.push(b); writeFileSync(join(dir, String(k).padStart(6, '0')), b); }
      const out = execFileSync('bash', ['-c', CLI, '_', SCAN, dir], { maxBuffer: 1e8 }).toString();
      const cli = new Map(out.replace(/\n$/, '').split('\n').map((l) => l.split('\t') as [string, string]));
      for (let k = 0; k < N; k++) {
        const name = String(k).padStart(6, '0');
        const u = ijsonProblem(new TextDecoder('utf-8').decode(cases[k])) ?? '';
        const c = cli.get(name) ?? '<missing>';
        total++;
        if (u !== c) diffs.push(`seed ${sd} #${name}: CLI=${c} UI=${u} hex=${Buffer.from(cases[k]!).toString('hex')}`);
      }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
  expect(total).toBe(N * seeds.length);
  expect(diffs.slice(0, 5)).toEqual([]);
}, 600000);

it('an empty array does not leave its member names behind (round-6 UI 2)', () => {
  expect(ijsonProblem('{"a":{"x":[]},"b":{"x":1}}')).toBeNull();
  expect(ijsonProblem('{"k":["x",{"e":[]},{"e":1,"b":true}]}')).toBeNull();
  expect(ijsonProblem('{"a":[],"a":1}')).toBe('duplicate member name');
});

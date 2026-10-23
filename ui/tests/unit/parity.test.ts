// CLI（zes-scan.sh）を基準とした UI 判定の差分の回帰テスト。入力はインラインの FileInput で作る（リポジトリのフィクスチャは CLI と共有のため追加しない）。
import { describe, expect, it } from 'vitest';
import { analyzeFiles } from '../../src/engine';
import type { FileInput } from '../../src/engine/types';

const BOM = '﻿';
const file = (relPath: string, text: string): FileInput => ({ relPath, name: relPath.split('/').pop()!, size: text.length, lastModified: 0, text, sha256: null, readState: 'read' });
const keys = async (fs: FileInput[]) => (await analyzeFiles(fs)).findings.map((f) => `${f.level} ${f.module} ${f.path ?? ''}`).sort();

describe('ロックファイル（CLI build_deps と同じ対象）', () => {
  it('yarn.lock v1（CRLF・BOM）と Berry', async () => {
    const v1 = `${BOM}# yarn lockfile v1\r\n\r\n"keyv@^6.0.0", keyv@6:\r\n  version "6.0.0"\r\n  resolved "x"\r\n`;
    const berry = '__metadata:\n  version: 6\n\n"@cacheable/memory@npm:^2.2.1":\n  version: 2.2.1\n';
    const k = await keys([file('p/yarn.lock', v1), file('q/yarn.lock', berry)]);
    expect(k).toContain('CRITICAL §15 p/yarn.lock');
    expect(k).toContain('CRITICAL §15 q/yarn.lock');
  });
  it('pnpm-lock.yaml（/name@ver・peer 接尾辞・引用符付きスコープ）', async () => {
    const t = `lockfileVersion: '6.0'\r\n\r\npackages:\r\n\r\n  /flat-cache@6.1.24:\r\n    resolution: {integrity: x}\r\n  '@cacheable/utils@2.5.1(peer@1.0.0)':\r\n    resolution: {integrity: y}\r\n`;
    const r = await analyzeFiles([file('p/pnpm-lock.yaml', t)]);
    expect(r.findings.filter((f) => f.module === '§15').map((f) => f.detail.split(' ')[1]).sort()).toEqual(['@cacheable/utils@2.5.1', 'flat-cache@6.1.24']);
  });
  it('package-lock v1 の入れ子 dependencies（BOM 付き）', async () => {
    const t = BOM + JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: '1.0.0', dependencies: { ecto: { version: '5.0.1' } } } } });
    expect(await keys([file('p/package-lock.json', t)])).toContain('CRITICAL §15 p/package-lock.json');
  });
  it('package-lock の不正 JSON は errors[] に記録（fail closed）', async () => {
    const r = await analyzeFiles([file('p/package-lock.json', '{')]);
    expect(r.errors).toContainEqual({ module: '§15', reason: 'lockfile_parse_failed:p/package-lock.json' });
  });
  it('poetry.lock / uv.lock / pdm.lock（PEP 503 正規化）', async () => {
    const k = await keys([
      file('a/poetry.lock', '[[package]]\r\nname = "Guardrails__.AI"\r\nversion = "0.10.1"\r\n'),
      file('b/uv.lock', `${BOM}version = 1\n[[package]]\nname = "mistralai"\nversion = "2.4.6"\n`),
      file('c/pdm.lock', '[[package]]\nname = "Lightning"\nversion = "2.6.2"\n'),
    ]);
    expect(k).toEqual(expect.arrayContaining(['CRITICAL §15 a/poetry.lock', 'CRITICAL §15 b/uv.lock', 'CRITICAL §15 c/pdm.lock']));
  });
  it('Pipfile.lock（default / develop、== を除去）', async () => {
    const t = BOM + JSON.stringify({ _meta: {}, default: { Py2Ops: { version: '==2.2' } }, develop: { telnyx: { version: '==4.87.1' } } });
    const r = await analyzeFiles([file('p/Pipfile.lock', t)]);
    expect(r.findings.filter((f) => f.module === '§15').map((f) => f.detail.split(' ')[1]).sort()).toEqual(['py2ops@2.2', 'telnyx@4.87.1']);
  });
});

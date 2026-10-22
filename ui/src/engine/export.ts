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

/** UI のパスは投入フォルダからの相対パスのため、スキーマの絶対パス要件に合わせて "/" を前置し、その旨を errors[] に記録する。 */
export function toFindingsDoc(findings: Finding[], errors: ScanError[], bundle: string, startedAt: string, finishedAt: string): FindingsDoc {
  const errs: ScanError[] = [
    ...errors,
    { module: 'core', reason: 'ui:host_checks_not_performed' },
    { module: 'core', reason: 'ui:paths_relative_to_dropped_folder' },
  ];
  return {
    schema_version: '1.0',
    incident_bundle: bundle,
    scan_started_at: startedAt,
    scan_finished_at: finishedAt,
    scan_mode: 'full',
    status: 'partial',
    findings: findings.map((f) => {
      const o: FindingsDoc['findings'][number] = {
        id: f.id, level: f.level, module: f.module, campaign: f.campaign,
        path: f.path == null ? null : f.path.startsWith('/') ? f.path : '/' + f.path,
        detail: f.detail, evidence_hash: f.evidence_hash,
      };
      if (f.skillpact) o.skillpact = { ...f.skillpact, contract_path: f.skillpact.contract_path == null ? null : '/' + f.skillpact.contract_path.replace(/^\//, '') };
      return o;
    }),
    errors: errs,
  };
}

export class ImportError extends Error {}

/** CLI が出力した findings.json を読み込む（F-13）。JSON.parse と最小限の形の検査のみ。 */
export function parseFindingsDoc(text: string): { findings: Finding[]; errors: ScanError[]; bundle: string; status: string } {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new ImportError('findings.json を JSON として解析できません');
  }
  const d = doc as Partial<FindingsDoc>;
  if (!d || d.schema_version !== '1.0' || !Array.isArray(d.findings) || !Array.isArray(d.errors)) {
    throw new ImportError('ZES findings.json（schema_version 1.0）ではありません');
  }
  const findings: Finding[] = d.findings.flatMap((x) => {
    if (!x || typeof x.id !== 'string' || !SEVERITIES.includes(x.level) || typeof x.module !== 'string' || typeof x.detail !== 'string') return [];
    const f: Finding = {
      id: x.id, level: x.level, module: x.module, campaign: x.campaign ?? null, path: x.path ?? null,
      detail: x.detail, evidence_hash: String(x.evidence_hash ?? ''), ruleId: 'cli-import', source: 'cli-import',
    };
    if (x.skillpact) f.skillpact = x.skillpact;
    return [f];
  });
  return { findings, errors: d.errors.filter((e) => e && typeof e.module === 'string'), bundle: String(d.incident_bundle ?? ''), status: String(d.status ?? '') };
}

// Generating and loading findings.json (ZES schemas/findings.schema.json 1.2) (1.0 / 1.1 documents can be loaded too). No network is used.
// 1.1 is 1.0 plus optional fields (scan_roots, kind, subject, locators, related, evidence). 1.2 adds code / params,
// makes detail English and id v2.
import type { Finding, FindingEvidence, FindingLocator, FindingRelated, FindingSubject, ScanError, Severity, SkillPactFindingField } from './types';
import { SEVERITIES } from './types';
import { translate, type MsgKey } from '../i18n';

type DocFinding = {
  id: string; level: Severity; module: string; campaign: string | null; path: string | null;
  detail: string; evidence_hash: string; code?: string; params?: Record<string, string>; kind?: string; subject?: FindingSubject; locators?: FindingLocator[];
  related?: FindingRelated[]; evidence?: FindingEvidence; skillpact?: SkillPactFindingField;
};

export interface FindingsDoc {
  schema_version: '1.0' | '1.1' | '1.2';
  /** Real path of the CLI --root. The UI does not output it because its paths are relative to the loaded folder (no inspection scope is passed to ZET) */
  scan_roots?: string[];
  incident_bundle: string;
  scan_started_at: string;
  scan_finished_at: string;
  scan_mode: 'quick' | 'standard' | 'full' | 'worm' | 'skillpact';
  status: 'ok' | 'partial' | 'error';
  findings: DocFinding[];
  errors: ScanError[];
}

export interface ImportedDoc { findings: Finding[]; errors: ScanError[]; bundle: string; status: FindingsDoc['status']; dropped: number }

/** UI paths are relative to the loaded folder, so "/" is prefixed to meet the absolute-path requirement of the schema, and this is recorded in errors[].
 *  When findings.json imported from the CLI is included, its errors[] are carried over, and the incident_bundle and status of the source are reflected in errors[] / status. */
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
  const ids = new Set<string>();
  return {
    schema_version: '1.2',
    incident_bundle: bundle,
    scan_started_at: startedAt,
    scan_finished_at: finishedAt,
    scan_mode: 'full',
    status: imported?.status === 'error' ? 'error' : 'partial',
    // Findings with the same id are output only once (first wins)
    findings: findings.filter((f) => (ids.has(f.id) ? false : (ids.add(f.id), true))).map((f) => {
      const o: FindingsDoc['findings'][number] = {
        id: f.id, level: f.level, module: f.module, campaign: f.campaign,
        path: f.path == null ? null : f.path.startsWith('/') ? f.path : '/' + f.path,
        detail: f.detail, evidence_hash: f.evidence_hash,
      };
      const abs = (p: string) => (p.startsWith('/') ? p : '/' + p);
      if (f.code) { o.code = f.code; o.params = { ...(f.params ?? {}) }; }
      if (f.kind) o.kind = f.kind;
      if (f.subject) o.subject = { ...f.subject, fixed_versions: [...f.subject.fixed_versions] };
      if (f.locators?.length) o.locators = f.locators.map((l) => ({ ...l }));
      if (f.related?.length) o.related = f.related.map((r) => ({ relation: r.relation, path: abs(r.path) }));
      // Findings imported from 1.0 have no evidence. The kind cannot be determined from evidence_hash, so it cannot be called detail either; omit it
      if (f.evidence) o.evidence = { ...f.evidence };
      if (f.skillpact) o.skillpact = { ...f.skillpact, contract_path: f.skillpact.contract_path == null ? null : '/' + f.skillpact.contract_path.replace(/^\//, '') };
      return o;
    }),
    errors: errs.filter((e) => { const k = `${e.module}\0${e.reason}`; return seen.has(k) ? false : (seen.add(k), true); }),
  };
}

/** A findings.json that cannot be imported. key is the catalog message (ui.import.*); message is its English text. */
export class ImportError extends Error {
  constructor(readonly key: MsgKey) {
    super(translate('en', key));
  }
}

// ---- Validation against schemas/findings.schema.json (on import). Checks type, enum, pattern, required, additionalProperties:false ----
type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === 'string';
const strOrNull = (v: unknown) => v === null || isStr(v);
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const MODULE = /^§([1-9]|[1-4][0-9])$/;
const RFC3339 = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const BUNDLE = /^ZES-[0-9]{4}-[A-Z]{3}-[A-Z]+-V[0-9]+\.[0-9]+$/;
const EFFECTS = ['read', 'write', 'network', 'exec', 'spend', 'send'];
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
    && uniqueStrings(v['declared_effects'], EFFECTS) && uniqueStrings(v['observed_effects'], EFFECTS) && uniqueStrings(v['divergence'], EFFECTS);
}

const F_KEYS = ['id', 'level', 'module', 'campaign', 'path', 'detail', 'evidence_hash'];
const F11_KEYS = ['kind', 'subject', 'locators', 'related', 'evidence'];
const F12_KEYS = ['code', 'params'];
type Version = '1.0' | '1.1' | '1.2';
const LOC_FORMATS = ['json', 'jsonc', 'toml', 'yaml', 'ini', 'text', 'plist'];
const EV_KINDS = ['file', 'large_file', 'tree', 'symlink', 'detail'];
const absPath = (v: unknown) => isStr(v) && v.startsWith('/');
function validSubject(v: unknown): boolean {
  return isObj(v) && onlyKeys(v, ['ecosystem', 'package', 'version', 'safe_version', 'fixed_versions'], [])
    && (!('ecosystem' in v) || isStr(v['ecosystem'])) && (!('package' in v) || isStr(v['package']))
    && (!('version' in v) || strOrNull(v['version'])) && (!('safe_version' in v) || strOrNull(v['safe_version']))
    && (!('fixed_versions' in v) || (Array.isArray(v['fixed_versions']) && v['fixed_versions'].every(isStr)));
}
function validLocator(v: unknown): boolean {
  return isObj(v) && onlyKeys(v, ['format', 'pointer', 'line', 'line_sha256'], [])
    && (!('format' in v) || LOC_FORMATS.includes(v['format'] as string)) && (!('pointer' in v) || isStr(v['pointer']))
    && (!('line' in v) || (Number.isInteger(v['line']) && (v['line'] as number) >= 1))
    && (!('line_sha256' in v) || (isStr(v['line_sha256']) && SHA256.test(v['line_sha256'])));
}
/** Optional fields of findings 1.1 (schemas/findings.schema.json). Findings in a 1.0 document cannot have them */
function validFinding11(v: Obj): boolean {
  return (!('kind' in v) || (isStr(v['kind']) && /^[a-z0-9_.]+$/.test(v['kind'])))
    && (!('subject' in v) || validSubject(v['subject']))
    && (!('locators' in v) || (Array.isArray(v['locators']) && v['locators'].every(validLocator)))
    && (!('related' in v) || (Array.isArray(v['related']) && v['related'].every((r) => isObj(r) && onlyKeys(r, ['relation', 'path']) && isStr(r['relation']) && absPath(r['path']))))
    && (!('evidence' in v) || (isObj(v['evidence']) && onlyKeys(v['evidence'], ['kind', 'hash']) && EV_KINDS.includes(v['evidence']['kind'] as string)
      && isStr(v['evidence']['hash']) && SHA256.test(v['evidence']['hash'])));
}
/** findings 1.2: code (^[a-z0-9_.]+$) and params (string values, keys ^[a-z_]+$) */
function validFinding12(v: Obj): boolean {
  return (!('code' in v) || (isStr(v['code']) && /^[a-z0-9_.]+$/.test(v['code'])))
    && (!('params' in v) || (isObj(v['params']) && Object.entries(v['params']).every(([k, x]) => /^[a-z_]+$/.test(k) && isStr(x))));
}
export function validFinding(v: unknown, version: Version = '1.2'): v is FindingsDoc['findings'][number] {
  const extra = version === '1.2' ? [...F11_KEYS, ...F12_KEYS] : version === '1.1' ? F11_KEYS : [];
  if (!isObj(v) || !onlyKeys(v, [...F_KEYS, ...extra, 'skillpact'], F_KEYS) || !validFinding11(v) || !validFinding12(v)) return false;
  const ok = isStr(v['id']) && SHA256.test(v['id'])
    && SEVERITIES.includes(v['level'] as Severity)
    && isStr(v['module']) && MODULE.test(v['module'])
    && strOrNull(v['campaign'])
    && (v['path'] === null || (isStr(v['path']) && v['path'].startsWith('/')))
    && isStr(v['detail'])
    && isStr(v['evidence_hash']) && SHA256.test(v['evidence_hash']);
  if (!ok) return false;
  // §49 requires skillpact; everything else has no skillpact (if/then/else in the schema)
  return v['module'] === '§49' ? validSkillpact(v['skillpact']) : !('skillpact' in v);
}

export function validError(v: unknown): v is ScanError {
  return isObj(v) && onlyKeys(v, ['module', 'reason']) && isStr(v['module']) && (v['module'] === 'core' || MODULE.test(v['module'])) && isStr(v['reason']);
}

const TOP_KEYS = ['schema_version', 'incident_bundle', 'scan_started_at', 'scan_finished_at', 'scan_mode', 'status', 'findings', 'errors'];
const TOP_REQUIRED = TOP_KEYS;

/** Loads a findings.json output by the CLI (F-13). If the shape of the document as a whole is invalid, ImportError;
 *  findings / errors that do not match the schema are excluded without display and their count is returned in dropped (values that would break React children or search never enter the State). */
export function parseFindingsDoc(text: string): ImportedDoc {
  let doc: unknown;
  try {
    doc = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
  } catch {
    throw new ImportError('ui.import.not_json');
  }
  const ver = isObj(doc) ? doc['schema_version'] : undefined;
  if (!isObj(doc) || (ver !== '1.0' && ver !== '1.1' && ver !== '1.2') || !Array.isArray(doc['findings']) || !Array.isArray(doc['errors'])) {
    throw new ImportError('ui.import.not_findings');
  }
  const d = doc;
  const version = ver as Version;
  if (!onlyKeys(d, version !== '1.0' ? [...TOP_KEYS, 'scan_roots'] : TOP_KEYS, TOP_REQUIRED)
    || ('scan_roots' in d && !(Array.isArray(d['scan_roots']) && d['scan_roots'].every(absPath))) || !isStr(d['incident_bundle']) || !BUNDLE.test(d['incident_bundle'])
    || !isStr(d['scan_started_at']) || !RFC3339.test(d['scan_started_at']) || !isStr(d['scan_finished_at']) || !RFC3339.test(d['scan_finished_at'])
    || !MODES.includes(d['scan_mode'] as string) || !STATUSES.includes(d['status'] as string)) {
    throw new ImportError('ui.import.schema');
  }
  const rawF = d['findings'] as unknown[];
  const rawE = d['errors'] as unknown[];
  const findings: Finding[] = rawF.filter((x): x is DocFinding => validFinding(x, version)).map((x) => {
    const f: Finding = { id: x.id, level: x.level, module: x.module, campaign: x.campaign, path: x.path, detail: x.detail, evidence_hash: x.evidence_hash, ruleId: 'cli-import', source: 'cli-import' };
    if (x.kind) f.kind = x.kind;
    if (x.code) { f.code = x.code; f.params = { ...(x.params ?? {}) }; }
    if (x.subject) f.subject = { ecosystem: x.subject.ecosystem ?? '', package: x.subject.package ?? '', version: x.subject.version ?? null, safe_version: x.subject.safe_version ?? null, fixed_versions: [...(x.subject.fixed_versions ?? [])] };
    if (x.locators) f.locators = x.locators.map((l) => ({ ...l }));
    if (x.related) f.related = x.related.map((r) => ({ relation: r.relation, path: r.path }));
    if (x.evidence) f.evidence = { kind: x.evidence.kind, hash: x.evidence.hash };
    if (x.skillpact) f.skillpact = { ...x.skillpact, declared_effects: [...x.skillpact.declared_effects], observed_effects: [...x.skillpact.observed_effects], divergence: [...x.skillpact.divergence] };
    return f;
  });
  const errors = rawE.filter(validError).map((e) => ({ module: e.module, reason: e.reason }));
  return { findings, errors, bundle: d['incident_bundle'] as string, status: d['status'] as FindingsDoc['status'], dropped: rawF.length - findings.length + rawE.length - errors.length };
}

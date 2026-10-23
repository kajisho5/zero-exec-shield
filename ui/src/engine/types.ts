// 判定エンジンの型。ファイル内容（text）は FileInput にだけ存在し、出力の型には現れない（設計書 §6.3）。

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type DisplaySeverity = Severity | 'SAFE';
export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
export const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };

/** SkillPact 0.8 の 6 効果（spec §6）。順序も仕様どおり */
export type Effect = 'read' | 'write' | 'network' | 'exec' | 'spend' | 'send';
export const EFFECTS: Effect[] = ['read', 'write', 'network', 'exec', 'spend', 'send'];
export type Decision = 'allow' | 'ask' | 'deny';
export type Level = 'L1' | 'L2' | 'L3';

/** エンジンへの入力。text は判定にのみ使い、どの出力にも転記しない。 */
export interface FileInput {
  relPath: string;
  name: string;
  size: number;
  lastModified: number;
  /** UTF-8 として読んだ内容。サイズ超過・バイナリ・読み取り失敗は null */
  text: string | null;
  /** 内容の SHA-256（"sha256:" なしの 16 進）。読み取れなかった場合は null */
  sha256: string | null;
  readState: 'read' | 'skipped-size' | 'skipped-binary' | 'error';
}

export interface SkillPactFindingField {
  contract_path: string | null;
  contract_version: string | null;
  level: string | null;
  signed: boolean;
  author: string | null;
  declared_effects: string[];
  observed_effects: Effect[];
  policy_decision: string | null;
  l2_tested: boolean;
  divergence: string[];
  diff_anomaly: boolean;
}

/** findings 1.1 の任意項目（ZES schemas/findings.schema.json）。ファイル内容は含めない（pointer か、行番号と行の SHA-256 だけ） */
export interface FindingSubject { ecosystem: string; package: string; version: string | null; safe_version: string | null; fixed_versions: string[] }
export type LocatorFormat = 'json' | 'jsonc' | 'toml' | 'yaml' | 'ini' | 'text' | 'plist';
export interface FindingLocator { format: LocatorFormat; pointer?: string; line?: number; line_sha256?: string }
export interface FindingRelated { relation: string; path: string }
export type EvidenceKind = 'file' | 'large_file' | 'tree' | 'symlink' | 'detail';
export interface FindingEvidence { kind: EvidenceKind; hash: string }

export interface Finding {
  id: string;
  level: Severity;
  module: string;
  campaign: string | null;
  /** 投入フォルダからの相対パス。貼り付け由来は null */
  path: string | null;
  /** 固定テンプレート由来の説明（ファイル由来の文字列を連結しない） */
  detail: string;
  evidence_hash: string;
  kind?: string;
  /** findings 1.2: message id (catalog key f.<code>) and its values. Absent on findings imported from 1.0 / 1.1 */
  code?: string;
  params?: Record<string, string>;
  subject?: FindingSubject;
  locators?: FindingLocator[];
  related?: FindingRelated[];
  /** 種類つきの証跡（CLI から取り込んだ 1.0 の finding には無い） */
  evidence?: FindingEvidence;
  skillpact?: SkillPactFindingField;
  ruleId: string;
  source: 'ui' | 'cli-import';
}

export interface BlastRadiusItem { path: string; kind: string; size: number }

export interface McpServerView {
  name: string;
  /** §13-4 で表示を許容した設定値（120 文字まで） */
  command: string;
  args: string;
  risk: 'high' | 'medium' | 'none';
  tokens: string[];
}
export interface McpConfigView { path: string; servers: McpServerView[]; parseError: boolean }

export interface UsesRef { ref: string; kind: 'sha' | 'tag' | 'local' | 'compromised' }
export interface WorkflowView { path: string; uses: UsesRef[]; prTarget: boolean }

export interface ExtensionView { path: string; name: string; dangerous: string[]; allUrls: boolean; unofficialUpdate: boolean }

export interface SkillPactDivergence { effect: Effect; why: 'none' | 'scope'; sensitive?: boolean; durable?: boolean; level: Severity }
export interface DiffAnomaly { previousVersion: string; previousPath: string; widened: string[]; identity: 'same' | 'changed' | 'unsigned'; level: Severity }
export type RuleStatus = 'hit' | 'clear' | 'n/a' | 'undetermined';
export interface RuleResult { ruleNo: number; title: string; level: Severity; status: RuleStatus }

export interface SkillPactAnalysis {
  skillId: string;
  name: string;
  contract: {
    found: boolean;
    path: string | null;
    /** none: 契約なし / unparseable: I-JSON 不正 / unsupported: 未対応の contract_version / invalid: 部分検査で不合格 / ok */
    status: 'none' | 'unparseable' | 'unsupported' | 'invalid' | 'ok';
    problem: string | null;
    contractVersion: string | null;
    errors: string[];
  };
  skillName: string | null;
  skillVersion: string | null;
  /** ZES の部分検査に合格した場合のみ 'L1'。L2/L3 は ZES では判定しない */
  level: string | null;
  /** integrity.signatures がある（ZES は署名を検証しない） */
  signed: boolean;
  signers: string[];
  author: string | null;
  declared: Effect[];
  observed: Effect[];
  divergence: SkillPactDivergence[];
  diffAnomaly: DiffAnomaly | null;
  results: RuleResult[];
  maxLevel: Severity | null;
  counts: Partial<Record<Severity, number>>;
}

export interface ScanError { module: string; reason: string }

export interface EngineStats {
  files: number;
  read: number;
  skippedSize: number;
  skippedBinary: number;
  errors: number;
  zeroByteDecoys: number;
}

export interface CheckDef { id: string; module: string; title: string }

export interface EngineResult {
  findings: Finding[];
  skillpact: SkillPactAnalysis[];
  blastRadius: BlastRadiusItem[];
  viewers: { mcp: McpConfigView[]; actions: WorkflowView[]; extensions: ExtensionView[] };
  errors: ScanError[];
  stats: EngineStats;
  /** 実行したチェック ID（SAFE = 該当なしのチェック数の算出に使う） */
  checksRun: string[];
}

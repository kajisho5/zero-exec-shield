// Types of the evaluation engine. File content (text) exist only in FileInput and never appear in the output types (design doc §6.3).
import type { MsgKey } from '../i18n';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type DisplaySeverity = Severity | 'SAFE';
export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
export const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };

/** The 6 effects of SkillPact 0.8 (spec §6). In the order of the spec */
export type Effect = 'read' | 'write' | 'network' | 'exec' | 'spend' | 'send';
export const EFFECTS: Effect[] = ['read', 'write', 'network', 'exec', 'spend', 'send'];
export type Decision = 'allow' | 'ask' | 'deny';
export type Level = 'L1' | 'L2' | 'L3';

/** Input to the engine. text is used only for evaluation and is never copied into any output. */
export interface FileInput {
  relPath: string;
  name: string;
  size: number;
  lastModified: number;
  /** Contents read as UTF-8 (null when over the size limit, binary or unreadable), as fileReader.ts gives it: TextDecoder
   *  has removed one leading BOM and turned invalid UTF-8 into U+FFFD. The rules remove no further BOM (the CLI ignores
   *  exactly one leading BOM per file as well). */
  text: string | null;
  /** SHA-256 of the content (hex without "sha256:"). null if it could not be read */
  sha256: string | null;
  readState: 'read' | 'skipped-size' | 'skipped-binary' | 'error';
  /** The first 4096 bytes of a file named .git or commondir (Git pointer files are read as bytes, like the CLI's
   *  git_read_pointer: a BOM or a NUL is seen as it is). Absent for other files */
  head?: Uint8Array;
  /** The file itself when the generic read skipped it for its size: the engine reads the first GIT_CONFIG_MAX bytes of a Git
   *  config from it (git.ts). Never read for anything else, never part of the output */
  blob?: Blob;
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

/** Optional fields of findings 1.1 (ZES schemas/findings.schema.json). No file content (only a pointer, or a line number and the SHA-256 of the line) */
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
  /** Path relative to the loaded folder. null for pasted input */
  path: string | null;
  /** Description from a fixed template (never concatenates strings from files) */
  detail: string;
  evidence_hash: string;
  kind?: string;
  /** findings 1.2: message id (catalog key f.<code>) and its values. Absent on findings imported from 1.0 / 1.1 */
  code?: string;
  params?: Record<string, string>;
  subject?: FindingSubject;
  locators?: FindingLocator[];
  related?: FindingRelated[];
  /** Typed evidence (absent from 1.0 findings imported from the CLI) */
  evidence?: FindingEvidence;
  skillpact?: SkillPactFindingField;
  ruleId: string;
  source: 'ui' | 'cli-import';
}

export interface BlastRadiusItem { path: string; kind: string; size: number }

export interface McpServerView {
  name: string;
  /** Config value allowed for display by §13-4 (up to 120 characters) */
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
export interface RuleResult { ruleNo: number; /** catalog key of the rule name (ui.sp.rule.*) */ title: MsgKey; level: Severity; status: RuleStatus }

export interface SkillPactAnalysis {
  skillId: string;
  name: string;
  contract: {
    found: boolean;
    path: string | null;
    /** none: no contract / unparseable: invalid I-JSON / unsupported: unsupported contract_version / invalid: failed the partial checks / ok */
    status: 'none' | 'unparseable' | 'unsupported' | 'invalid' | 'ok';
    problem: string | null;
    contractVersion: string | null;
    errors: string[];
  };
  skillName: string | null;
  skillVersion: string | null;
  /** 'L1' only if the ZES partial checks pass. ZES does not evaluate L2/L3 */
  level: string | null;
  /** integrity.signatures is present (ZES does not verify signatures) */
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
  /** IDs of the checks that ran (used to compute SAFE = the number of checks with no match) */
  checksRun: string[];
  /** Git files the CLI would read but the browser cannot, because they are outside the dropped folder (a gitdir: /
   *  commondir / include target, as written in the file that points to it). Shown as a CLI-only note */
  gitOutside: string[];
}

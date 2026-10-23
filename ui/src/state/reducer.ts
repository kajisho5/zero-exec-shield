import type { EngineResult, Finding, Severity } from '../engine';
import { SEVERITIES } from '../engine';
import type { ImportedDoc } from '../engine/export';
import type { TabId } from '../tabs/definitions';

export interface ScanState {
  phase: 'idle' | 'reading' | 'analyzing' | 'done' | 'error';
  /** 実行中（最後に開始した）スキャンの ID。クリア・新しいスキャンで置き換わり、古いスキャンの進捗・結果は捨てる */
  scanId: number | null;
  progress: { processed: number; total: number };
  result: EngineResult | null;
  pasteFindings: Finding[];
  imported: ImportedDoc | null;
  errorMessage: string | null;
  durationMs: number;
  startedAt: string | null;
  finishedAt: string | null;
  ui: {
    activeTab: TabId;
    severityFilter: Set<Severity>;
    query: string;
    moduleFilter: string | null;
    selectedSkillId: string | null;
  };
}

export type Action =
  | { type: 'SCAN_START'; scanId: number; total: number; startedAt: string }
  | { type: 'SCAN_PROGRESS'; scanId: number; processed: number; phase?: 'reading' | 'analyzing' }
  | { type: 'SCAN_RESULT'; scanId: number; result: EngineResult; finishedAt: string; durationMs: number }
  | { type: 'SCAN_FAIL'; scanId: number; message: string }
  | { type: 'PASTE_RESULT'; findings: Finding[] }
  | { type: 'IMPORT_FINDINGS'; doc: NonNullable<ScanState['imported']> }
  | { type: 'SET_TAB'; tab: TabId }
  | { type: 'TOGGLE_SEVERITY'; severity: Severity }
  | { type: 'SET_QUERY'; query: string }
  | { type: 'SET_MODULE'; module: string | null }
  | { type: 'SELECT_SKILL'; id: string | null }
  | { type: 'CLEAR' };

export const initialState: ScanState = {
  phase: 'idle',
  scanId: null,
  progress: { processed: 0, total: 0 },
  result: null,
  pasteFindings: [],
  imported: null,
  errorMessage: null,
  durationMs: 0,
  startedAt: null,
  finishedAt: null,
  ui: { activeTab: 'overview', severityFilter: new Set(SEVERITIES), query: '', moduleFilter: null, selectedSkillId: null },
};

export function reducer(s: ScanState, a: Action): ScanState {
  // 置き換えられた（クリア後・次のスキャン開始後の）スキャンの進捗・結果は反映しない
  if ((a.type === 'SCAN_PROGRESS' || a.type === 'SCAN_RESULT' || a.type === 'SCAN_FAIL') && a.scanId !== s.scanId) return s;
  switch (a.type) {
    case 'SCAN_START':
      // 前回のスキャン結果は消す（新しい startedAt と古い結果・finishedAt を混ぜて表示・書き出ししない）
      return { ...s, phase: 'reading', scanId: a.scanId, progress: { processed: 0, total: a.total }, startedAt: a.startedAt, finishedAt: null, durationMs: 0, result: null, errorMessage: null };
    case 'SCAN_PROGRESS':
      return { ...s, phase: a.phase ?? s.phase, progress: { ...s.progress, processed: a.processed } };
    case 'SCAN_RESULT':
      return { ...s, phase: 'done', scanId: null, result: a.result, finishedAt: a.finishedAt, durationMs: a.durationMs, ui: { ...s.ui, selectedSkillId: a.result.skillpact[0]?.skillId ?? null } };
    case 'SCAN_FAIL':
      return { ...s, phase: 'error', scanId: null, errorMessage: a.message };
    case 'PASTE_RESULT':
      return { ...s, pasteFindings: a.findings };
    case 'IMPORT_FINDINGS':
      return { ...s, imported: a.doc, phase: s.phase === 'idle' ? 'done' : s.phase };
    case 'SET_TAB':
      // モジュールはタブごとに違う。前のタブのモジュールで絞ったままにしない（選択欄は「すべて」なのに全行が消える）
      return { ...s, ui: { ...s.ui, activeTab: a.tab, moduleFilter: a.tab === s.ui.activeTab ? s.ui.moduleFilter : null } };
    case 'TOGGLE_SEVERITY': {
      const next = new Set(s.ui.severityFilter);
      if (next.has(a.severity)) next.delete(a.severity);
      else next.add(a.severity);
      return { ...s, ui: { ...s.ui, severityFilter: next } };
    }
    case 'SET_QUERY':
      return { ...s, ui: { ...s.ui, query: a.query } };
    case 'SET_MODULE':
      return { ...s, ui: { ...s.ui, moduleFilter: a.module } };
    case 'SELECT_SKILL':
      return { ...s, ui: { ...s.ui, selectedSkillId: a.id } };
    case 'CLEAR':
      return { ...initialState, ui: { ...initialState.ui, severityFilter: new Set(SEVERITIES), activeTab: s.ui.activeTab } };
  }
}

/** 画面に出す全 finding（フォルダ判定 + 貼り付け + CLI 取り込み）。id で重複を除き、先に出たもの（フォルダ判定 > 貼り付け > 取り込み）を残す
 *  （自分が書き出した findings.json を取り込み直しても二重に数えない）。 */
export function allFindings(s: ScanState): Finding[] {
  const seen = new Set<string>();
  return [...(s.result?.findings ?? []), ...s.pasteFindings, ...(s.imported?.findings ?? [])].filter((f) => (seen.has(f.id) ? false : (seen.add(f.id), true)));
}

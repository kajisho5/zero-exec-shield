// §7.2 の 18 タブ（順序固定）。各タブは module または campaign で検出を絞り込む。
import type { Finding } from '../engine';
import type { MsgKey } from '../i18n';

export type TabId =
  | 'overview' | 'skillpact' | 'teampcp' | 'chaindrop' | 'pypi' | 'solana' | 'post-shaihulud' | 'mcp' | 'actions'
  | 'extensions' | 'build-hooks' | 'model-supply' | 'persistence' | 'anti-forensics' | 'hf' | 'ebpf' | 'ai-assistant' | 'sigstore';

export interface TabDef {
  id: TabId;
  /** Catalog key of the tab name (ui.tab.*) */
  label: MsgKey;
  modules: string[];
  campaigns: string[];
  /** ブラウザでは判定できないホスト状態の検査（0 件 = 安全と誤認させないため案内を出す）。カタログのキー（ui.cli_note.*） */
  cliOnlyNote?: MsgKey;
  viewer?: 'mcp' | 'actions' | 'extensions' | 'skillpact';
}

export const TABS: TabDef[] = [
  { id: 'overview', label: 'ui.tab.overview', modules: [], campaigns: [] },
  { id: 'skillpact', label: 'ui.tab.skillpact', modules: ['§49'], campaigns: [], viewer: 'skillpact' },
  { id: 'teampcp', label: 'ui.tab.teampcp', modules: [], campaigns: ['teampcp-mini-shai-hulud'] },
  { id: 'chaindrop', label: 'ui.tab.chaindrop', modules: [], campaigns: ['chaindrop-keyv', 'shai-hulud-chaindrop'] },
  { id: 'pypi', label: 'ui.tab.pypi', modules: [], campaigns: ['litellm-oct2026', 'pypi-oct2026'] },
  { id: 'solana', label: 'ui.tab.solana', modules: [], campaigns: ['solana-typosquat'] },
  { id: 'post-shaihulud', label: 'ui.tab.post_shaihulud', modules: ['§25'], campaigns: ['post-shaihulud', 'sckit-memos'], cliOnlyNote: 'ui.cli_note.post_shaihulud' },
  { id: 'mcp', label: 'ui.tab.mcp', modules: ['§17', '§20', '§37'], campaigns: ['mcp-poisoning'], viewer: 'mcp' },
  { id: 'actions', label: 'ui.tab.actions', modules: ['§21', '§22', '§38'], campaigns: [], viewer: 'actions' },
  { id: 'extensions', label: 'ui.tab.extensions', modules: ['§24', '§42'], campaigns: [], viewer: 'extensions' },
  { id: 'build-hooks', label: 'ui.tab.build_hooks', modules: ['§27'], campaigns: [] },
  { id: 'model-supply', label: 'ui.tab.model_supply', modules: ['§32'], campaigns: [] },
  { id: 'persistence', label: 'ui.tab.persistence', modules: ['§10', '§26', '§30', '§31', '§33'], campaigns: [], cliOnlyNote: 'ui.cli_note.persistence' },
  { id: 'anti-forensics', label: 'ui.tab.anti_forensics', modules: ['§35'], campaigns: [], cliOnlyNote: 'ui.cli_note.anti_forensics' },
  { id: 'hf', label: 'ui.tab.hf', modules: ['§36'], campaigns: [] },
  { id: 'ebpf', label: 'ui.tab.ebpf', modules: ['§40'], campaigns: [], cliOnlyNote: 'ui.cli_note.ebpf' },
  { id: 'ai-assistant', label: 'ui.tab.ai_assistant', modules: ['§7', '§41'], campaigns: [], cliOnlyNote: 'ui.cli_note.ai_assistant' },
  { id: 'sigstore', label: 'ui.tab.sigstore', modules: ['§28', '§43', '§48'], campaigns: [], cliOnlyNote: 'ui.cli_note.sigstore' },
];

export function findingsForTab(tab: TabDef, findings: Finding[]): Finding[] {
  if (tab.id === 'overview') return findings;
  return findings.filter((f) => tab.modules.includes(f.module) || (f.campaign !== null && tab.campaigns.includes(f.campaign)));
}

export const CLI_COMMAND = './zes-scan.sh --full --json';

// §7.2 の 18 タブ（順序固定）。各タブは module または campaign で検出を絞り込む。
import type { Finding } from '../engine';

export type TabId =
  | 'overview' | 'skillpact' | 'teampcp' | 'chaindrop' | 'pypi' | 'solana' | 'post-shaihulud' | 'mcp' | 'actions'
  | 'extensions' | 'build-hooks' | 'model-supply' | 'persistence' | 'anti-forensics' | 'hf' | 'ebpf' | 'ai-assistant' | 'sigstore';

export interface TabDef {
  id: TabId;
  label: string;
  modules: string[];
  campaigns: string[];
  /** ブラウザでは判定できないホスト状態の検査（0 件 = 安全と誤認させないため案内を出す） */
  cliOnlyNote?: string;
  viewer?: 'mcp' | 'actions' | 'extensions' | 'skillpact';
}

export const TABS: TabDef[] = [
  { id: 'overview', label: '総合', modules: [], campaigns: [] },
  { id: 'skillpact', label: 'SkillPact', modules: ['§49'], campaigns: [], viewer: 'skillpact' },
  { id: 'teampcp', label: 'TeamPCP', modules: [], campaigns: ['teampcp-mini-shai-hulud'] },
  { id: 'chaindrop', label: 'ChainDrop', modules: [], campaigns: ['chaindrop-keyv', 'shai-hulud-chaindrop'] },
  { id: 'pypi', label: 'PyPI', modules: [], campaigns: ['litellm-oct2026', 'pypi-oct2026'] },
  { id: 'solana', label: 'Solana', modules: [], campaigns: ['solana-typosquat'] },
  { id: 'post-shaihulud', label: 'Post-ShaiHulud', modules: ['§25'], campaigns: ['post-shaihulud', 'sckit-memos'], cliOnlyNote: 'プロセス（cargo-install 偽装等）とホームディレクトリ外のバイナリは CLI で確認してください' },
  { id: 'mcp', label: 'MCP', modules: ['§17', '§20', '§37'], campaigns: ['mcp-poisoning'], viewer: 'mcp' },
  { id: 'actions', label: 'GitHub Actions', modules: ['§21', '§22', '§38'], campaigns: [], viewer: 'actions' },
  { id: 'extensions', label: 'ブラウザ拡張', modules: ['§24', '§42'], campaigns: [], viewer: 'extensions' },
  { id: 'build-hooks', label: 'ビルドフック', modules: ['§27'], campaigns: [] },
  { id: 'model-supply', label: 'モデル供給網', modules: ['§32'], campaigns: [] },
  { id: 'persistence', label: '永続化', modules: ['§10', '§26', '§30', '§31', '§33'], campaigns: [], cliOnlyNote: 'crontab / launchctl / systemd のホスト状態は CLI で確認してください' },
  { id: 'anti-forensics', label: 'アンチフォレンジック', modules: ['§35'], campaigns: [], cliOnlyNote: 'noatime マウント・auditd / OpenBSM の稼働状態はブラウザから判定できません' },
  { id: 'hf', label: 'HF', modules: ['§36'], campaigns: [] },
  { id: 'ebpf', label: 'eBPF/LD_PRELOAD', modules: ['§40'], campaigns: [], cliOnlyNote: 'bpftool / lsmod / /proc / /sys/fs/bpf はブラウザから判定できません' },
  { id: 'ai-assistant', label: 'AIアシスタント', modules: ['§7', '§41'], campaigns: [], cliOnlyNote: 'Cursor / Copilot のインストール済みバージョンは CLI で確認してください' },
  { id: 'sigstore', label: 'Sigstore/SBOM', modules: ['§28', '§43', '§48'], campaigns: [], cliOnlyNote: 'インストール済み cosign のバージョンは CLI で確認してください' },
];

export function findingsForTab(tab: TabDef, findings: Finding[]): Finding[] {
  if (tab.id === 'overview') return findings;
  return findings.filter((f) => tab.modules.includes(f.module) || (f.campaign !== null && tab.campaigns.includes(f.campaign)));
}

export const CLI_COMMAND = './zes-scan.sh --full --json';

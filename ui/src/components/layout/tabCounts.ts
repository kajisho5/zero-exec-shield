import { SEVERITY_RANK, type Finding, type Severity } from '@/engine';
import { TABS, findingsForTab, type TabId } from '@/tabs/definitions';

export interface TabCount { n: number; max: Severity | undefined }

export function maxLevel(fs: Finding[]): Severity | undefined {
  return fs.reduce<Severity | undefined>((m, f) => (!m || SEVERITY_RANK[f.level] > SEVERITY_RANK[m] ? f.level : m), undefined);
}

export function tabCounts(findings: Finding[]): Record<TabId, TabCount> {
  return Object.fromEntries(TABS.map((t) => { const fs = findingsForTab(t, findings); return [t.id, { n: fs.length, max: maxLevel(fs) }]; })) as Record<TabId, TabCount>;
}

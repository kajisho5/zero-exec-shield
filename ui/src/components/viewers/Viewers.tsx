// Viewers for MCP / GitHub Actions / browser extensions (design doc §10.6). One sheet + a list of rows.
// Only shows the config values allowed in §13-4 (command/args, uses:, permission names). Values are well-ground <code>, dangerous tokens a SeverityTag.
// Actions references: SHA-pinned = SAFE tag, tag reference = HIGH, possibly poisoned = CRITICAL, local = neutral tag.
import type { ReactNode } from 'react';
import type { DisplaySeverity, ExtensionView, McpConfigView, WorkflowView } from '@/engine';
import { useLang, type MsgKey } from '@/i18n';
import { cn } from '@/lib/utils';
import { visibleOpt, visiblePath } from '@/lib/visiblePath';
import { PathText } from '@/components/PathText';
import { SeverityTag } from '@/components/severity/SeverityTag';
import { Tag } from '@/components/severity/Tag';
import { Card } from '@/components/ui/card';

function Viewer({ title, note, children, testid }: { title: string; note: string; children: ReactNode; testid: string }) {
  return (
    <Card data-testid={testid} className="px-5 py-4">
      <h2 className="text-base font-semibold">{title}</h2>
      <p className="mt-0.5 text-xs text-muted-foreground">{note}</p>
      {children}
    </Card>
  );
}

const Rows = ({ children }: { children: ReactNode }) => <ul className="mt-2 divide-y divide-border border-y border-border">{children}</ul>;
const Code = ({ children, className }: { children: ReactNode; className?: string }) => (
  <code className={cn('block min-w-0 truncate rounded-sm bg-muted px-2 py-0.5 font-mono text-[13px]', className)}>{children}</code>
);

export function McpViewer({ configs }: { configs: McpConfigView[] }) {
  const { t } = useLang();
  if (!configs.length) return null;
  return (
    <Viewer title={t('ui.viewer.mcp')} note={t('ui.viewer.mcp_desc')} testid="mcp-viewer">
      {configs.map((c) => (
        <div key={c.path} className="mt-4">
          <div className="flex flex-wrap items-center gap-2">
            <PathText path={c.path} wrap className="text-[13px]" />
            {c.parseError && <SeverityTag level="HIGH">{t('ui.viewer.unparsable')}</SeverityTag>}
          </div>
          <Rows>
            {c.servers.map((s, i) => (
              <li key={i} className="grid grid-cols-1 gap-1.5 py-2.5 sm:grid-cols-[160px_minmax(0,1fr)_auto] sm:items-center sm:gap-3" data-risk={s.risk}>
                <span className="truncate text-sm font-medium">{visiblePath(s.name) || '—'}</span>
                <Code className={s.risk === 'high' ? 'text-critical' : s.risk === 'medium' ? 'text-medium' : undefined}>{visiblePath(`${s.command} ${s.args}`)}</Code>
                <span className="flex flex-wrap gap-1">{s.tokens.map((t) => <SeverityTag key={t} level={s.risk === 'high' ? 'CRITICAL' : 'MEDIUM'} className="font-mono">{visiblePath(t)}</SeverityTag>)}</span>
              </li>
            ))}
            {!c.servers.length && <li className="py-2.5 text-[13px] text-muted-foreground">{t('ui.viewer.no_servers')}</li>}
          </Rows>
        </div>
      ))}
    </Viewer>
  );
}

const KIND: Record<WorkflowView['uses'][number]['kind'], { label: MsgKey; level: DisplaySeverity | null }> = {
  sha: { label: 'ui.viewer.pinned', level: 'SAFE' },
  tag: { label: 'ui.viewer.tag', level: 'HIGH' },
  compromised: { label: 'ui.viewer.poisoned', level: 'CRITICAL' },
  local: { label: 'ui.viewer.local', level: null },
};

export function ActionsViewer({ workflows }: { workflows: WorkflowView[] }) {
  const { t } = useLang();
  if (!workflows.length) return null;
  return (
    <Viewer title={t('ui.viewer.actions')} note={t('ui.viewer.actions_desc')} testid="actions-viewer">
      {workflows.map((w) => (
        <div key={w.path} className="mt-4">
          <div className="flex flex-wrap items-center gap-2">
            <PathText path={w.path} wrap className="text-[13px]" />
            {w.prTarget && <SeverityTag level="HIGH" className="font-mono">pull_request_target</SeverityTag>}
          </div>
          <Rows>
            {w.uses.map((u) => {
              const k = KIND[u.kind];
              return (
                <li key={u.ref} className="flex items-center justify-between gap-3 py-2" data-kind={u.kind}>
                  <Code className="w-fit max-w-full">{visiblePath(u.ref)}</Code>
                  {k.level ? <SeverityTag level={k.level}>{t(k.label)}</SeverityTag> : <Tag>{t(k.label)}</Tag>}
                </li>
              );
            })}
          </Rows>
        </div>
      ))}
    </Viewer>
  );
}

export function ExtensionViewer({ manifests }: { manifests: ExtensionView[] }) {
  const { t } = useLang();
  if (!manifests.length) return null;
  return (
    <Viewer title={t('ui.viewer.ext')} note={t('ui.viewer.ext_desc')} testid="extension-viewer">
      <Rows>
        {manifests.map((m) => (
          <li key={m.path} className="flex flex-wrap items-center gap-2 py-2.5">
            <span className="min-w-0 flex-1 basis-48">
              <span className="block truncate text-sm font-medium">{visibleOpt(m.name) || t('ui.viewer.unnamed')}</span>
              <PathText path={m.path} className="text-xs" />
            </span>
            {m.dangerous.map((p) => <SeverityTag key={p} level="HIGH" className="font-mono">{visiblePath(p)}</SeverityTag>)}
            {m.allUrls && <SeverityTag level="HIGH" className="font-mono">&lt;all_urls&gt;</SeverityTag>}
            {m.unofficialUpdate && <SeverityTag level="CRITICAL">{t('ui.viewer.update_url')}</SeverityTag>}
            {!m.dangerous.length && !m.allUrls && !m.unofficialUpdate && <span className="text-xs text-muted-foreground">{t('ui.viewer.clean')}</span>}
          </li>
        ))}
      </Rows>
    </Viewer>
  );
}

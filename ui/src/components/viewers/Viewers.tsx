// MCP / GitHub Actions / ブラウザ拡張のビューア（設計書 §10.6）。台紙 1 枚＋行の一覧。
// §13-4 で許容した設定値（command/args、uses:、パーミッション名）だけを表示する。値は凹みの <code>、危険なトークンは SeverityTag。
// Actions の参照: SHA 固定 = SAFE のタグ、タグ参照 = HIGH、汚染の可能性 = CRITICAL、ローカル = 無彩色のタグ。
import type { ReactNode } from 'react';
import type { DisplaySeverity, ExtensionView, McpConfigView, WorkflowView } from '@/engine';
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
  if (!configs.length) return null;
  return (
    <Viewer title="MCP 設定ビューア" note="command / args のみ表示（120 文字まで）。危険なコマンドを CRITICAL、要確認を MEDIUM で示します" testid="mcp-viewer">
      {configs.map((c) => (
        <div key={c.path} className="mt-4">
          <div className="flex flex-wrap items-center gap-2">
            <PathText path={c.path} wrap className="text-[13px]" />
            {c.parseError && <SeverityTag level="HIGH">JSON として解析できません</SeverityTag>}
          </div>
          <Rows>
            {c.servers.map((s, i) => (
              <li key={i} className="grid grid-cols-1 gap-1.5 py-2.5 sm:grid-cols-[160px_minmax(0,1fr)_auto] sm:items-center sm:gap-3" data-risk={s.risk}>
                <span className="truncate text-sm font-medium">{visiblePath(s.name) || '—'}</span>
                <Code className={s.risk === 'high' ? 'text-critical' : s.risk === 'medium' ? 'text-medium' : undefined}>{visiblePath(`${s.command} ${s.args}`)}</Code>
                <span className="flex flex-wrap gap-1">{s.tokens.map((t) => <SeverityTag key={t} level={s.risk === 'high' ? 'CRITICAL' : 'MEDIUM'} className="font-mono">{visiblePath(t)}</SeverityTag>)}</span>
              </li>
            ))}
            {!c.servers.length && <li className="py-2.5 text-[13px] text-muted-foreground">サーバー定義なし</li>}
          </Rows>
        </div>
      ))}
    </Viewer>
  );
}

const KIND: Record<WorkflowView['uses'][number]['kind'], { label: string; level: DisplaySeverity | null }> = {
  sha: { label: 'SHA 固定', level: 'SAFE' },
  tag: { label: 'タグ参照', level: 'HIGH' },
  compromised: { label: '汚染の可能性', level: 'CRITICAL' },
  local: { label: 'ローカル', level: null },
};

export function ActionsViewer({ workflows }: { workflows: WorkflowView[] }) {
  if (!workflows.length) return null;
  return (
    <Viewer title="GitHub Actions ビューア" note="uses: の参照を、SHA 固定 / タグ参照 / 汚染の可能性 / ローカルに分けて表示します" testid="actions-viewer">
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
                  {k.level ? <SeverityTag level={k.level}>{k.label}</SeverityTag> : <Tag>{k.label}</Tag>}
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
  if (!manifests.length) return null;
  return (
    <Viewer title="ブラウザ拡張ビューア" note="危険なパーミッション名と <all_urls> を示します（update_url の値は表示しません）" testid="extension-viewer">
      <Rows>
        {manifests.map((m) => (
          <li key={m.path} className="flex flex-wrap items-center gap-2 py-2.5">
            <span className="min-w-0 flex-1 basis-48">
              <span className="block truncate text-sm font-medium">{visibleOpt(m.name) || '（名前なし）'}</span>
              <PathText path={m.path} className="text-xs" />
            </span>
            {m.dangerous.map((p) => <SeverityTag key={p} level="HIGH" className="font-mono">{visiblePath(p)}</SeverityTag>)}
            {m.allUrls && <SeverityTag level="HIGH" className="font-mono">&lt;all_urls&gt;</SeverityTag>}
            {m.unofficialUpdate && <SeverityTag level="CRITICAL">update_url: 公式ストア以外</SeverityTag>}
            {!m.dangerous.length && !m.allUrls && !m.unofficialUpdate && <span className="text-xs text-muted-foreground">危険な設定なし</span>}
          </li>
        ))}
      </Rows>
    </Viewer>
  );
}

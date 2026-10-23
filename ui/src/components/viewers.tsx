// MCP / GitHub Actions / ブラウザ拡張ビューア。§13-4 で許容した設定値（command/args、uses:、パーミッション名）のみ表示する。
import type { ExtensionView, McpConfigView, WorkflowView } from '../engine';
import { Card, Pill } from './ui';

export function McpViewer({ configs }: { configs: McpConfigView[] }) {
  if (!configs.length) return null;
  return (
    <Card className="p-5" data-testid="mcp-viewer">
      <h3 className="font-semibold">MCP 設定ビューア</h3>
      <p className="text-xs text-subtle">command / args のみ表示（120 文字まで）。危険なコマンドを赤、要確認を黄で強調</p>
      {configs.map((c) => (
        <div key={c.path} className="mt-3">
          <div className="break-all font-mono text-[13px] text-muted">{c.path}{c.parseError && <span className="ml-2 text-high">（JSON として解析できません）</span>}</div>
          <ul className="mt-1 divide-y divide-border rounded-lg border border-border">
            {c.servers.map((s, i) => (
              <li key={i} className="grid grid-cols-1 gap-1 px-3 py-2 sm:grid-cols-[160px_minmax(0,1fr)_auto] sm:items-center sm:gap-3" data-risk={s.risk}>
                <span className="truncate text-sm">{s.name || '—'}</span>
                <code className={`truncate font-mono text-[13px] ${s.risk === 'high' ? 'text-critical' : s.risk === 'medium' ? 'text-medium' : ''}`}>{s.command} {s.args}</code>
                <span className="flex flex-wrap gap-1">{s.tokens.map((t) => <Pill key={t} tone={s.risk === 'high' ? 'critical' : 'medium'}>{t}</Pill>)}</span>
              </li>
            ))}
            {!c.servers.length && <li className="px-3 py-2 text-sm text-subtle">サーバー定義なし</li>}
          </ul>
        </div>
      ))}
    </Card>
  );
}

export function ActionsViewer({ workflows }: { workflows: WorkflowView[] }) {
  if (!workflows.length) return null;
  const tone = { sha: 'safe', tag: 'high', local: 'muted', compromised: 'critical' } as const;
  const label = { sha: 'SHA 固定', tag: 'タグ参照', local: 'ローカル', compromised: '汚染の可能性' } as const;
  return (
    <Card className="p-5" data-testid="actions-viewer">
      <h3 className="font-semibold">GitHub Actions ビューア</h3>
      <p className="text-xs text-subtle">uses: の参照を SHA 固定 / タグ参照で色分け</p>
      {workflows.map((w) => (
        <div key={w.path} className="mt-3">
          <div className="break-all font-mono text-[13px] text-muted">{w.path}{w.prTarget && <span className="ml-2 text-high">pull_request_target</span>}</div>
          <ul className="mt-1 divide-y divide-border rounded-lg border border-border">
            {w.uses.map((u) => (
              <li key={u.ref} className="flex items-center justify-between gap-3 px-3 py-2" data-kind={u.kind}>
                <code className="min-w-0 truncate font-mono text-[13px]">{u.ref}</code>
                <Pill tone={tone[u.kind]}>{label[u.kind]}</Pill>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </Card>
  );
}

export function ExtensionViewer({ manifests }: { manifests: ExtensionView[] }) {
  if (!manifests.length) return null;
  return (
    <Card className="p-5" data-testid="extension-viewer">
      <h3 className="font-semibold">ブラウザ拡張ビューア</h3>
      <p className="text-xs text-subtle">危険パーミッション名と &lt;all_urls&gt; を強調（update_url の値は表示しません）</p>
      <ul className="mt-3 divide-y divide-border rounded-lg border border-border">
        {manifests.map((m) => (
          <li key={m.path} className="flex flex-wrap items-center gap-2 px-3 py-2">
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm">{m.name || '（名前なし）'}</span>
              <span className="block truncate font-mono text-xs text-subtle">{m.path}</span>
            </span>
            {m.dangerous.map((p) => <Pill key={p} tone="high">{p}</Pill>)}
            {m.allUrls && <Pill tone="high">&lt;all_urls&gt;</Pill>}
            {m.unofficialUpdate && <Pill tone="critical">update_url: 公式ストア以外</Pill>}
            {!m.dangerous.length && !m.allUrls && !m.unofficialUpdate && <span className="text-xs text-subtle">危険な設定なし</span>}
          </li>
        ))}
      </ul>
    </Card>
  );
}

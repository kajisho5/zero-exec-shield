import { useEffect, useMemo, useRef, useState, type DragEvent } from 'react';
import { SEVERITIES, type BlastRadiusItem, type Finding, type Severity } from '../engine';
import { CLI_COMMAND } from '../tabs/definitions';
import { Button, Card, Icon, SEV_STYLE, SeverityBadge, useCopy } from './ui';

export const PASTE_MAX = 1_000_000;

// ---- 入力 ---------------------------------------------------------------------------------
export function InputArea({ busy, onDrop, onPick, onPaste, onImport }: {
  busy: boolean;
  onDrop(dt: DataTransfer): void;
  onPick(files: FileList): void;
  onPaste(text: string): void;
  onImport(file: File): void;
}) {
  const dir = useRef<HTMLInputElement>(null);
  const imp = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const [text, setText] = useState('');
  useEffect(() => {
    // React の型に無い属性のため DOM で付与（D&D 非対応環境のフォルダ選択フォールバック、F-02）
    dir.current?.setAttribute('webkitdirectory', '');
    dir.current?.setAttribute('directory', '');
  }, []);
  const drop = (e: DragEvent) => { e.preventDefault(); setOver(false); if (!busy) onDrop(e.dataTransfer); };
  return (
    <Card className="grid grid-cols-[1.1fr_1fr] gap-4 p-4">
      <div
        onDragOver={(e) => { e.preventDefault(); setOver(true); }}
        onDragLeave={() => setOver(false)}
        onDrop={drop}
        data-testid="dropzone"
        className={`flex flex-col justify-between rounded-xl border border-dashed p-4 ${over ? 'border-accent bg-[#0b1f2a]' : 'border-border-strong'}`}
      >
        <div className="flex items-start gap-3">
          <Icon name="folder" size={32} className="mt-1 text-accent" />
          <div>
            <div className="text-lg font-semibold">フォルダをドラッグ＆ドロップ</div>
            <div className="mt-1 flex flex-wrap items-center gap-2 text-sm text-muted">
              または
              <button type="button" disabled={busy} onClick={() => dir.current?.click()} className="h-7 rounded-lg border border-accent px-4 text-accent hover:bg-[#0b1f2a] disabled:opacity-40">フォルダを選択…</button>
              <span className="text-xs text-subtle">webkitdirectory</span>
            </div>
            <input ref={dir} type="file" multiple hidden data-testid="dir-input" onChange={(e) => { if (e.target.files?.length) onPick(e.target.files); e.target.value = ''; }} />
          </div>
        </div>
        <div className="mt-4 border-t border-border pt-3 text-xs leading-relaxed text-subtle">
          ファイル内容は判定にのみ使用し、画面表示・保存・送信を行いません。<br />
          1 ファイル 2 MiB 超は未判定として計上（0 件扱いしない）。
          <button type="button" className="ml-2 text-accent underline-offset-2 hover:underline" onClick={() => imp.current?.click()}>CLI の findings.json を読み込む</button>
          <input ref={imp} type="file" accept=".json,application/json" hidden data-testid="import-input" onChange={(e) => { const f = e.target.files?.[0]; if (f) onImport(f); e.target.value = ''; }} />
        </div>
      </div>
      <div className="flex flex-col">
        <div className="mb-2 flex items-baseline gap-3">
          <h2 className="font-semibold">テキスト貼り付け判定</h2>
          <span className="text-xs text-subtle">C2 ドメイン/IP・base64・exec(・curl</span>
        </div>
        <textarea
          value={text}
          maxLength={PASTE_MAX}
          onChange={(e) => setText(e.target.value)}
          aria-label="判定するテキスト"
          data-testid="paste"
          placeholder={'ログ・コマンド履歴・設定断片を貼り付け\n（貼り付け内容は再表示しません）'}
          className="h-[84px] resize-none rounded-lg border border-border-strong bg-surface-2 px-3 py-2 text-sm placeholder:text-subtle"
        />
        <div className="mt-2 flex items-center justify-between">
          <span className="text-xs text-subtle">{text.length.toLocaleString()} / {PASTE_MAX.toLocaleString()} 文字</span>
          <Button variant="primary" disabled={!text.trim()} onClick={() => { onPaste(text); setText(''); }} data-testid="paste-submit">判定する</Button>
        </div>
      </div>
    </Card>
  );
}

// ---- サマリ・フィルタ -------------------------------------------------------------------
export function SummaryCards({ findings, active, safe, onToggle }: { findings: Finding[]; active: Set<Severity>; safe: { clear: number; total: number }; onToggle(s: Severity): void }) {
  const n = (s: Severity) => findings.filter((f) => f.level === s).length;
  const card = (s: 'CRITICAL' | 'HIGH' | 'MEDIUM') => {
    const st = SEV_STYLE[s];
    const on = active.has(s);
    return (
      <button key={s} type="button" aria-pressed={on} onClick={() => onToggle(s)} data-testid={`card-${s}`}
        className={`relative overflow-hidden rounded-xl border bg-surface p-4 text-left ${on ? st.border : 'border-border opacity-60'}`}>
        <span className={`absolute inset-y-0 left-0 w-1 ${st.bar}`} aria-hidden="true" />
        <div className={`flex items-center gap-1.5 text-xs font-medium ${st.fg}`}><Icon name={st.icon} size={12} />{s}</div>
        <div className="mt-1 text-3xl font-semibold" data-testid={`count-${s}`}>{n(s)}</div>
        <div className="text-xs text-subtle">{s === 'MEDIUM' ? `LOW ${n('LOW')} ・ INFO ${n('INFO')} を含みます` : `クリックで絞込（${on ? '選択中' : '解除中'}）`}</div>
      </button>
    );
  };
  return (
    <div className="grid grid-cols-4 gap-4">
      {card('CRITICAL')}{card('HIGH')}{card('MEDIUM')}
      <div className="relative overflow-hidden rounded-xl border border-border bg-surface p-4" data-testid="card-SAFE">
        <span className="absolute inset-y-0 left-0 w-1 bg-safe" aria-hidden="true" />
        <div className="flex items-center gap-1.5 text-xs font-medium text-safe"><Icon name="safe" size={12} />SAFE</div>
        <div className="mt-1 flex items-baseline gap-2"><span className="text-3xl font-semibold">{safe.clear}</span><span className="text-xs text-subtle">/ {safe.total} チェック非該当</span></div>
        <div className="text-xs text-subtle">ブラウザ判定範囲のみ</div>
      </div>
    </div>
  );
}

export function FindingsToolbar({ findings, active, onToggle, query, onQuery, module, onModule }: {
  findings: Finding[]; active: Set<Severity>; onToggle(s: Severity): void; query: string; onQuery(q: string): void; module: string | null; onModule(m: string | null): void;
}) {
  const modules = useMemo(() => [...new Set(findings.map((f) => f.module))].sort((a, b) => Number(a.slice(1)) - Number(b.slice(1))), [findings]);
  return (
    <div className="flex items-center gap-2 max-[1100px]:flex-wrap" role="group" aria-label="重大度フィルタ">
      <span className="mr-1 text-xs text-muted">重大度</span>
      {SEVERITIES.map((s) => {
        const st = SEV_STYLE[s];
        const on = active.has(s);
        return (
          <button key={s} type="button" aria-pressed={on} onClick={() => onToggle(s)} data-testid={`filter-${s}`}
            className={`inline-flex h-7 shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 text-xs font-medium ${on ? `${st.fg} ${st.bg} ${st.border}` : 'border-border-strong text-subtle'}`}>
            <Icon name={st.icon} size={10} />{s} {findings.filter((f) => f.level === s).length}
          </button>
        );
      })}
      <label className="ml-auto flex h-8 min-w-32 flex-1 basis-40 items-center gap-2 rounded-lg border border-border-strong bg-surface-2 px-3 text-muted">
        <Icon name="search" size={14} />
        <input value={query} onChange={(e) => onQuery(e.target.value)} placeholder="パス・キャンペーンで検索" aria-label="パス・キャンペーンで検索" className="w-full bg-transparent text-sm text-text outline-none placeholder:text-subtle" data-testid="search" />
      </label>
      <select value={module ?? ''} onChange={(e) => onModule(e.target.value || null)} aria-label="モジュールで絞込" className="h-8 shrink-0 rounded-lg border border-border-strong bg-surface-2 px-2 text-sm">
        <option value="">モジュール: すべて</option>
        {modules.map((m) => <option key={m} value={m}>{m}</option>)}
      </select>
    </div>
  );
}

// ---- 検出一覧（自前の仮想スクロール、§13-9） -------------------------------------------
const ROW = 50;
export function FindingsTable({ findings, empty }: { findings: Finding[]; empty: string }) {
  const copy = useCopy();
  const [top, setTop] = useState(0);
  const height = Math.min(Math.max(findings.length, 1) * ROW, 560);
  const start = Math.max(0, Math.floor(top / ROW) - 5);
  const end = Math.min(findings.length, Math.ceil((top + height) / ROW) + 5);
  return (
    <Card className="overflow-hidden" data-testid="findings-table">
      <div role="row" className="grid grid-cols-[120px_80px_180px_1fr_56px] items-center gap-3 border-b border-border bg-surface-2 px-4 py-2 text-xs text-muted">
        <span role="columnheader">重大度</span><span role="columnheader">モジュール</span><span role="columnheader">キャンペーン</span><span role="columnheader">パス ／ 詳細</span><span role="columnheader" className="text-right">コピー</span>
      </div>
      {findings.length === 0 ? (
        <div className="px-4 py-10 text-center text-sm text-subtle">{empty}</div>
      ) : (
        <div role="table" aria-rowcount={findings.length} className="relative overflow-y-auto" style={{ height }} onScroll={(e) => setTop(e.currentTarget.scrollTop)}>
          <div style={{ height: findings.length * ROW }}>
            {findings.slice(start, end).map((f, i) => (
              <div key={f.id} role="row" data-testid="finding-row" data-level={f.level} style={{ position: 'absolute', top: (start + i) * ROW, left: 0, right: 0, height: ROW }}
                className="grid grid-cols-[120px_80px_180px_1fr_56px] items-center gap-3 border-b border-border px-4 hover:bg-surface-2">
                <span role="cell"><SeverityBadge level={f.level} /></span>
                <span role="cell" className="text-sm">{f.module}</span>
                <span role="cell" className="truncate text-sm" title={f.campaign ?? undefined}>{f.campaign ?? '—'}</span>
                <span role="cell" className="min-w-0">
                  <span className="block truncate font-mono text-[13px]" title={f.path ?? undefined}>{f.path ?? '（貼り付けテキスト）'}</span>
                  <span className="block truncate text-xs text-subtle">{f.detail}</span>
                </span>
                <span role="cell" className="text-right">
                  {f.path && <Button variant="icon" aria-label={`パスをコピー: ${f.path}`} title="パスをコピー" onClick={() => copy(f.path!)}><Icon name="copy" /></Button>}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </Card>
  );
}

// ---- 右カラム -----------------------------------------------------------------------------
export function BlastRadiusPanel({ items }: { items: BlastRadiusItem[] }) {
  const copy = useCopy();
  const size = (n: number) => (n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`);
  return (
    <Card className="p-5" data-testid="blast-radius">
      <div className="flex items-center gap-2">
        <Icon name="key" className="text-high" />
        <h2 className="text-lg font-semibold">Blast Radius</h2>
        <span className="rounded-md border border-border-strong bg-surface-2 px-2 text-xs text-muted">存在のみ・内容非表示</span>
      </div>
      <p className="mt-1 text-xs text-subtle">ローテーション対象となるシークレットのパス一覧（§14 / §19 / §9.5）</p>
      <div className="mt-3 grid grid-cols-[1fr_auto] border-b border-border pb-1 text-xs text-muted"><span>パス</span><span>サイズ</span></div>
      <ul className="max-h-[260px] overflow-y-auto">
        {items.length === 0 && <li className="py-4 text-sm text-subtle">該当なし（投入フォルダ内のみ判定）</li>}
        {items.map((b) => (
          <li key={b.path} className="grid grid-cols-[auto_1fr_auto] items-center gap-2 border-b border-border py-2">
            <Icon name="key" size={14} className="text-subtle" />
            <span className="truncate font-mono text-[13px]" title={b.path}>{b.path}</span>
            <span className="text-xs text-subtle">{size(b.size)}</span>
          </li>
        ))}
      </ul>
      <div className="mt-3 flex items-center justify-between">
        <span className="text-xs text-subtle">{items.length} 件・内容は読み取り・表示しません</span>
        <Button disabled={!items.length} onClick={() => copy(items.map((b) => b.path).join('\n'), 'パス一覧')}><Icon name="copy" size={14} />パス一覧をコピー</Button>
      </div>
      <p className="mt-2 text-xs text-subtle">手順: 検出 → 一覧提示 → ローテーション → 再構築</p>
    </Card>
  );
}

export function CliOnlyNotice({ note, compact }: { note?: string; compact?: boolean }) {
  const copy = useCopy();
  return (
    <Card className={compact ? 'flex items-center gap-3 px-4 py-3' : 'p-5'} data-testid="cli-only">
      {!compact && <div className="flex items-center gap-2"><Icon name="terminal" className="text-accent" /><h2 className="font-semibold">ホスト検査は CLI で実施</h2></div>}
      <p className={`${compact ? '' : 'mt-2'} text-sm text-muted`}>{note ?? 'プロセス・ネットワーク接続・カーネル・eBPF・マウント状態はブラウザから確認できないため、0 件 ＝ 安全と表示しません。'}</p>
      <div className={`${compact ? 'ml-auto' : 'mt-3'} flex items-center justify-between gap-3 rounded-lg border border-border bg-bg px-3 py-2`}>
        <code className="font-mono text-[13px]">{CLI_COMMAND}</code>
        <Button variant="icon" aria-label="コマンドをコピー" onClick={() => copy(CLI_COMMAND, 'コマンド')}><Icon name="copy" size={14} /></Button>
      </div>
    </Card>
  );
}

export function UndeterminedCard({ skippedSize, skippedBinary, decoys, errors }: { skippedSize: number; skippedBinary: number; decoys: number; errors: number }) {
  const rows: [string, number][] = [['サイズ超過（2 MiB 超）', skippedSize], ['バイナリ（判定対象外）', skippedBinary], ['シンボリックリンク先 不明（0 バイトのデコイ）', decoys], ['読み取り失敗', errors]];
  return (
    <Card className="p-5" data-testid="undetermined">
      <div className="flex items-center gap-2"><Icon name="info" className="text-info" /><h2 className="font-semibold">未判定（0 件扱いしない）</h2></div>
      <ul className="mt-2">
        {rows.map(([k, v]) => <li key={k} className="flex justify-between border-b border-border py-2 text-sm last:border-0"><span>{k}</span><span>{v}</span></li>)}
      </ul>
    </Card>
  );
}

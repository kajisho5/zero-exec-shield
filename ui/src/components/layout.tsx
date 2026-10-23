import { useEffect, useRef, useState, type KeyboardEvent } from 'react';
import { IOC, SEVERITY_RANK, type Finding, type Severity } from '../engine';
import { TABS, findingsForTab, type TabId } from '../tabs/definitions';
import { Button, Icon, SEV_STYLE } from './ui';

export function Header({ onExport, onClear, canExport }: { onExport(): void; onClear(): void; canExport: boolean }) {
  return (
    <header className="flex min-h-16 flex-wrap items-center gap-x-4 gap-y-2 border-b border-border px-4 py-3 sm:px-8">
      <Icon name="brand" size={32} className="text-accent" />
      <div className="flex items-center gap-2">
        <h1 className="text-lg font-semibold">Zero-Exec Shield</h1>
        <span className="rounded-md border border-border-strong bg-surface-2 px-1.5 text-xs text-muted" title="準拠仕様 v5.2">v0.1.0</span>
      </div>
      <div className="min-w-0 leading-tight sm:ml-4">
        <div className="text-[11px] text-subtle">incident_bundle</div>
        <div className="break-all font-mono text-xs text-muted" data-testid="bundle">{IOC.incident_bundle}</div>
      </div>
      <div className="ml-auto flex flex-wrap items-center justify-end gap-3">
        <span className="inline-flex h-7 items-center gap-2 rounded-full border border-safe bg-safe-bg px-3 text-xs text-safe" title="この画面は外部と一切通信しません（CSP connect-src 'none'）">
          <span className="h-2 w-2 rounded-full bg-safe" aria-hidden="true" />
          オフライン・外部通信ゼロ
        </span>
        <Button onClick={onExport} disabled={!canExport} data-testid="export">JSON 出力</Button>
        <Button onClick={onClear}>クリア</Button>
      </div>
    </header>
  );
}

function maxLevel(fs: Finding[]): Severity | undefined {
  return fs.reduce<Severity | undefined>((m, f) => (!m || SEVERITY_RANK[f.level] > SEVERITY_RANK[m] ? f.level : m), undefined);
}

export function TabBar({ active, findings, onSelect }: { active: TabId; findings: Finding[]; onSelect(id: TabId): void }) {
  const scroller = useRef<HTMLDivElement>(null);
  const refs = useRef<Record<string, HTMLButtonElement | null>>({});
  const [menu, setMenu] = useState(false);
  const counts = Object.fromEntries(TABS.map((t) => { const fs = findingsForTab(t, findings); return [t.id, { n: fs.length, max: maxLevel(fs) }]; }));

  useEffect(() => { refs.current[active]?.scrollIntoView({ block: 'nearest', inline: 'nearest' }); }, [active]);

  const move = (e: KeyboardEvent, i: number) => {
    const n = TABS.length;
    const to = e.key === 'ArrowRight' ? (i + 1) % n : e.key === 'ArrowLeft' ? (i - 1 + n) % n : e.key === 'Home' ? 0 : e.key === 'End' ? n - 1 : -1;
    if (to >= 0) { e.preventDefault(); refs.current[TABS[to]!.id]?.focus(); }
  };
  const scrollBy = (d: number) => scroller.current?.scrollBy({ left: d, behavior: 'smooth' });

  return (
    <nav className="relative flex h-12 items-stretch border-b border-border px-4 sm:px-8">
      <Button variant="icon" className="my-auto mr-2 shrink-0" aria-label="タブを左へスクロール" onClick={() => scrollBy(-320)}><Icon name="chevron-left" /></Button>
      <div ref={scroller} role="tablist" aria-label="検査カテゴリ" className="scrollbar-none flex min-w-0 flex-1 snap-x items-stretch overflow-x-auto [mask-image:linear-gradient(to_right,transparent,black_24px,black_calc(100%-24px),transparent)]">
        {TABS.map((t, i) => {
          const c = counts[t.id]!;
          const sel = t.id === active;
          return (
            <button
              key={t.id}
              ref={(el) => { refs.current[t.id] = el; }}
              role="tab"
              id={`tab-${t.id}`}
              aria-selected={sel}
              aria-controls={`panel-${t.id}`}
              tabIndex={sel ? 0 : -1}
              aria-label={`${t.label}、検出 ${c.n} 件${c.max ? `、最大 ${c.max}` : ''}`}
              onClick={() => onSelect(t.id)}
              onKeyDown={(e) => { move(e, i); if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(t.id); } }}
              className={`relative flex shrink-0 snap-start items-center gap-2 whitespace-nowrap px-4 text-sm ${sel ? 'font-semibold text-text' : 'text-muted hover:text-text'}`}
            >
              {t.label}
              {c.n > 0 && <span className={`rounded px-1.5 text-xs ${c.max ? `${SEV_STYLE[c.max].fg} ${SEV_STYLE[c.max].bg}` : ''}`}>{c.n}</span>}
              {sel && <span className="absolute inset-x-2 bottom-0 h-0.5 bg-accent" aria-hidden="true" />}
            </button>
          );
        })}
      </div>
      <Button variant="icon" className="my-auto ml-2 shrink-0" aria-label="タブを右へスクロール" onClick={() => scrollBy(320)}><Icon name="chevron-right" /></Button>
      <div className="relative my-auto ml-2 shrink-0">
        <Button aria-haspopup="menu" aria-expanded={menu} onClick={() => setMenu((m) => !m)} data-testid="all-tabs">
          すべてのタブ <span className="text-xs text-muted">{TABS.length}</span> <Icon name="chevron-down" size={14} />
        </Button>
        {menu && (
          <ul role="menu" className="absolute right-0 top-10 z-40 max-h-[70vh] w-60 overflow-auto rounded-xl border border-border-strong bg-surface-2 py-1 shadow-xl">
            {TABS.map((t) => (
              <li key={t.id} role="none">
                <button role="menuitem" className="flex w-full items-center justify-between px-4 py-2 text-left text-sm hover:bg-[#242424]" onClick={() => { onSelect(t.id); setMenu(false); }}>
                  {t.label}
                  {counts[t.id]!.n > 0 && <span className="text-xs text-muted">{counts[t.id]!.n}</span>}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </nav>
  );
}

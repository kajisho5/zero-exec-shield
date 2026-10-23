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
        <span className="rounded-md border border-border-strong bg-surface-2 px-1.5 text-xs text-muted" title="準拠仕様 v5.2">v0.2.0</span>
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

  // 「すべてのタブ」メニュー: Escape・外側クリックで閉じる。Escape ではボタンへフォーカスを戻す
  const menuWrap = useRef<HTMLDivElement>(null);
  const menuButton = () => menuWrap.current?.querySelector<HTMLButtonElement>('[data-testid=all-tabs]');
  const menuItems = () => [...(menuWrap.current?.querySelectorAll<HTMLButtonElement>('[role=menuitem]') ?? [])];
  useEffect(() => {
    if (!menu) return;
    menuItems()[0]?.focus();
    const onDown = (e: PointerEvent) => { if (!menuWrap.current?.contains(e.target as Node)) setMenu(false); };
    const onKey = (e: globalThis.KeyboardEvent) => { if (e.key === 'Escape') { e.preventDefault(); setMenu(false); menuButton()?.focus(); } };
    document.addEventListener('pointerdown', onDown);
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('pointerdown', onDown); document.removeEventListener('keydown', onKey); };
  }, [menu]);
  const menuKey = (e: KeyboardEvent) => {
    const items = menuItems();
    const i = items.indexOf(document.activeElement as HTMLButtonElement);
    const to = e.key === 'ArrowDown' ? (i + 1) % items.length : e.key === 'ArrowUp' ? (i - 1 + items.length) % items.length : e.key === 'Home' ? 0 : e.key === 'End' ? items.length - 1 : -1;
    if (to >= 0) { e.preventDefault(); items[to]?.focus(); }
    if (e.key === 'Tab') setMenu(false);
  };

  const move = (e: KeyboardEvent, i: number) => {
    const n = TABS.length;
    const to = e.key === 'ArrowRight' ? (i + 1) % n : e.key === 'ArrowLeft' ? (i - 1 + n) % n : e.key === 'Home' ? 0 : e.key === 'End' ? n - 1 : -1;
    if (to >= 0) { e.preventDefault(); refs.current[TABS[to]!.id]?.focus(); }
  };
  const scrollBy = (d: number) => scroller.current?.scrollBy({ left: d, behavior: 'smooth' });

  return (
    <nav className="relative flex h-12 items-stretch border-b border-border px-4 sm:px-8">
      {/* 狭い画面ではスクロールボタンを隠し、タブ列の幅を確保する（スワイプと「すべてのタブ」で移動できる） */}
      <div className="my-auto mr-2 hidden shrink-0 sm:flex"><Button variant="icon" aria-label="タブを左へスクロール" onClick={() => scrollBy(-320)}><Icon name="chevron-left" /></Button></div>
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
      <div className="my-auto ml-2 hidden shrink-0 sm:flex"><Button variant="icon" aria-label="タブを右へスクロール" onClick={() => scrollBy(320)}><Icon name="chevron-right" /></Button></div>
      <div ref={menuWrap} className="relative my-auto ml-2 shrink-0">
        <Button aria-haspopup="menu" aria-expanded={menu} aria-controls={menu ? 'all-tabs-menu' : undefined} onClick={() => setMenu((m) => !m)} data-testid="all-tabs">
          <span className="sr-only sm:not-sr-only">すべてのタブ</span> <span className="text-xs text-muted">{TABS.length}</span> <Icon name="chevron-down" size={14} />
        </Button>
        {menu && (
          <ul id="all-tabs-menu" role="menu" aria-label="すべてのタブ" onKeyDown={menuKey} className="absolute right-0 top-10 z-40 max-h-[70vh] w-60 overflow-auto rounded-xl border border-border-strong bg-surface-2 py-1 shadow-xl">
            {TABS.map((t) => (
              <li key={t.id} role="none">
                <button type="button" role="menuitem" tabIndex={-1} className="flex w-full items-center justify-between px-4 py-2 text-left text-sm hover:bg-[#242424]" onClick={() => { onSelect(t.id); setMenu(false); refs.current[t.id]?.focus(); }}>
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

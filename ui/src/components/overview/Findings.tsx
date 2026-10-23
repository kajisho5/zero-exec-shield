// 検出一覧（設計書 §10.3、§10.4）。台紙 1 枚。自前の仮想スクロール（行の高さを固定）。
// ≥640: 表（溝＋重大度 / パス・詳細 / キャンペーン / モジュール / コピー）、行 60px、見出し行は role="table" の中。
// <640: 1 件 96px のカード型の行。行を押すと詳細のシート（閉じるとフォーカスは押した行に戻る）。
import { useCallback, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { CircleDashed, Copy, ListFilter, Search } from 'lucide-react';
import type { Finding } from '@/engine';
import { cn } from '@/lib/utils';
import { virtualWindow } from '@/lib/virtualWindow';
import { visibleOpt, visiblePath } from '@/lib/visiblePath';
import { PathText } from '@/components/PathText';
import { SEV } from '@/components/severity/severity';
import { SeverityMark } from '@/components/severity/SeverityMark';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Sheet, SheetClose, SheetContent, SheetTrigger } from '@/components/ui/sheet';
import { useCopy } from '@/components/ui/toast';
import { Tip } from '@/components/ui/tooltip';

const ROW = 60;
const CARD_ROW = 96;
const COLS = 'grid grid-cols-[128px_minmax(0,1fr)_160px_88px_48px] max-xl:grid-cols-[120px_minmax(0,1fr)_128px_72px_48px] max-md:grid-cols-[112px_minmax(0,1fr)_128px_48px]';

/** 固定高の仮想スクロール。スクロール領域は 0 件のとき外れる（空の案内に替わる）ので、付け直したときと件数が変わったときに
 *  top を要素の実際の scrollTop に合わせ直す（古い top のままだと、0 に戻った領域に末尾の行だけを描いて一覧が空に見える）。 */
function useVirtual(n: number, row: number, maxHeight: number) {
  const [top, setTop] = useState(0);
  const el = useRef<HTMLElement | null>(null);
  const ref = useCallback((node: HTMLElement | null) => { el.current = node; setTop(node?.scrollTop ?? 0); }, []);
  useLayoutEffect(() => { setTop(el.current?.scrollTop ?? 0); }, [n]);
  return { ...virtualWindow(n, row, maxHeight, top), ref, onScroll: (e: React.UIEvent<HTMLElement>) => setTop(e.currentTarget.scrollTop) };
}

function Empty({ children }: { children: ReactNode }) {
  return (
    <div className="m-4 flex items-center justify-center gap-2 rounded-md border border-dashed border-input px-4 py-8 text-center text-[13px] text-muted-foreground">
      <CircleDashed aria-hidden="true" className="size-4 shrink-0" />{children}
    </div>
  );
}

export function ModuleSelect({ modules, value, onChange, className }: { modules: string[]; value: string | null; onChange(m: string | null): void; className?: string }) {
  return (
    <NativeSelect value={value ?? ''} onChange={(e) => onChange(e.target.value || null)} aria-label="モジュールで絞り込み" wrapperClassName={className}>
      <NativeSelectOption value="">モジュール: すべて</NativeSelectOption>
      {modules.map((m) => <NativeSelectOption key={m} value={m}>{m}</NativeSelectOption>)}
    </NativeSelect>
  );
}

export function FindingsTable({ findings, total, empty, query, onQuery, modules, module, onModule }: {
  findings: Finding[]; total: number; empty: string; query: string; onQuery(q: string): void; modules: string[]; module: string | null; onModule(m: string | null): void;
}) {
  const copy = useCopy();
  const v = useVirtual(findings.length, ROW, 600);
  return (
    <Card data-testid="findings-table" className="overflow-hidden">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-2 py-2.5 pr-4 pl-5">
        <h2 className="mr-auto flex items-baseline gap-2 text-base font-semibold">検出<span className="text-sm font-normal text-muted-foreground tabular-nums">{findings.length === total ? `${total} 件` : `${findings.length} / ${total} 件`}</span></h2>
        <Input icon={<Search aria-hidden="true" className="size-4 shrink-0" />} value={query} onChange={(e) => onQuery(e.target.value)} placeholder="パス・キャンペーンで検索" aria-label="パス・キャンペーンで検索" data-testid="search" className="w-[300px] max-lg:w-auto max-lg:flex-1 max-lg:basis-48" />
        <ModuleSelect modules={modules} value={module} onChange={onModule} className="w-[176px]" />
      </div>
      <div role="table" aria-label="検出一覧" aria-rowcount={findings.length + 1} className="border-t border-border">
        <div role="rowgroup">
          <div role="row" aria-rowindex={1} className={cn(COLS, 'h-8 items-center border-b border-border pr-4 pl-5 text-xs font-medium text-muted-foreground')}>
            <span role="columnheader">重大度</span>
            <span role="columnheader">パス / 詳細</span>
            <span role="columnheader">キャンペーン</span>
            <span role="columnheader" className="max-md:hidden">モジュール</span>
            <span role="columnheader"><span className="sr-only">コピー</span></span>
          </div>
        </div>
        {findings.length === 0 ? <Empty>{empty}</Empty> : (
          <div ref={v.ref} role="rowgroup" className="relative overflow-y-auto" style={{ height: v.height }} onScroll={v.onScroll}>
            <div style={{ height: findings.length * ROW }}>
              {findings.slice(v.start, v.end).map((f, i) => {
                const idx = v.start + i;
                return (
                  <div key={f.id} role="row" aria-rowindex={idx + 2} data-testid="finding-row" data-level={f.level}
                    style={{ position: 'absolute', top: idx * ROW, left: 0, right: 0, height: ROW }}
                    className={cn(COLS, 'items-start pt-[11px] pr-4 pl-5 hover:bg-accent')}>
                    <span aria-hidden="true" className={cn('absolute inset-y-0 left-0 w-1', SEV[f.level].bar)} />
                    <span aria-hidden="true" className="absolute right-0 bottom-0 left-1 h-px bg-border" />
                    <span role="cell" className="pt-0.5"><SeverityMark level={f.level} /></span>
                    <span role="cell" className="min-w-0 pr-4">
                      {f.path ? <PathText path={f.path} className="text-sm leading-5" /> : <span className="block text-sm leading-5 text-muted-foreground">（貼り付けテキスト）</span>}
                      <span className="mt-0.5 block truncate text-[12.5px] text-muted-foreground" title={visiblePath(f.detail)}>{visiblePath(f.detail)}</span>
                    </span>
                    <span role="cell" className={cn('min-w-0 truncate pr-3 text-[13px] leading-5', !f.campaign && 'text-muted-foreground')} title={visibleOpt(f.campaign) ?? undefined}>
                      {visibleOpt(f.campaign) ?? '—'}
                      <span className="block text-muted-foreground md:hidden">{f.module}</span>
                    </span>
                    <span role="cell" className="text-[13px] leading-5 text-muted-foreground max-md:hidden">{f.module}</span>
                    <span role="cell" className="-mt-[3px] flex justify-end">
                      {f.path && (
                        <Tip label="パスをコピー" side="left">
                          {/* コピーは元の値のまま（利用者が求めたのはそのパス）。読み上げ名だけ目印付きの表示用 */}
                          <Button variant="ghost" size="icon-sm" aria-label={`パスをコピー: ${visiblePath(f.path)}`} onClick={() => copy(f.path!)}><Copy /></Button>
                        </Tip>
                      )}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}

/** <640 の一覧: 検索（44px）とモジュールのシート、カード型の行、詳細のシート。 */
export function FindingList({ findings, empty, query, onQuery, modules, module, onModule }: {
  findings: Finding[]; empty: string; query: string; onQuery(q: string): void; modules: string[]; module: string | null; onModule(m: string | null): void;
}) {
  const copy = useCopy();
  const v = useVirtual(findings.length, CARD_ROW, CARD_ROW * 6);
  const [detail, setDetail] = useState<Finding | null>(null);
  const [filterOpen, setFilterOpen] = useState(false);
  const opener = useRef<HTMLButtonElement | null>(null);
  const byId = useMemo(() => new Map(findings.map((f) => [f.id, f])), [findings]);
  return (
    <>
      <div className="flex gap-2">
        <Input icon={<Search aria-hidden="true" className="size-4 shrink-0" />} value={query} onChange={(e) => onQuery(e.target.value)} placeholder="パス・キャンペーンで検索" aria-label="パス・キャンペーンで検索" data-testid="search" className="h-11 flex-1" />
        <Sheet open={filterOpen} onOpenChange={setFilterOpen}>
          {/* Trigger にすると、閉じたとき（Escape・選択・閉じる）に Radix がフォーカスをこのボタンへ戻す */}
          <SheetTrigger asChild>
            <Button variant="outline" size="icon-touch" aria-label={`モジュールで絞り込み（${module ?? 'すべて'}）`} className="relative">
              <ListFilter />
              {module && <span aria-hidden="true" className="absolute top-2 right-2 size-1.5 rounded-full bg-foreground" />}
            </Button>
          </SheetTrigger>
          <SheetContent title="モジュールで絞り込み" className="pb-[max(env(safe-area-inset-bottom),12px)]">
            <ul className="overflow-y-auto px-2 pt-2">
              {[null, ...modules].map((m) => (
                <li key={m ?? ''}>
                  <SheetClose asChild>
                    <button type="button" aria-pressed={m === module} onClick={() => onModule(m)} className={cn('flex h-11 w-full items-center rounded-md px-3 text-left text-[15px] hover:bg-accent', m === module && 'bg-accent font-semibold')}>
                      {m ?? 'すべて'}
                    </button>
                  </SheetClose>
                </li>
              ))}
            </ul>
          </SheetContent>
        </Sheet>
      </div>
      <Card data-testid="findings-table" className="overflow-hidden">
        {findings.length === 0 ? <Empty>{empty}</Empty> : (
          <div ref={v.ref} role="list" aria-label={`検出 ${findings.length} 件`} className="relative overflow-y-auto" style={{ height: v.height }} onScroll={v.onScroll}>
            <div style={{ height: findings.length * CARD_ROW }}>
              {findings.slice(v.start, v.end).map((f, i) => {
                const idx = v.start + i;
                return (
                  <div key={f.id} role="listitem" data-testid="finding-row" data-level={f.level} style={{ position: 'absolute', top: idx * CARD_ROW, left: 0, right: 0, height: CARD_ROW }}>
                    <span aria-hidden="true" className={cn('absolute inset-y-0 left-0 z-10 w-1', SEV[f.level].bar)} />
                    <span aria-hidden="true" className="absolute right-0 bottom-0 left-1 h-px bg-border" />
                    <button type="button" data-finding={f.id} onClick={(e) => { opener.current = e.currentTarget; setDetail(byId.get(f.id) ?? null); }}
                      aria-label={`${f.level} ${f.path ? visiblePath(f.path) : '貼り付けテキスト'} の詳細`}
                      className="flex h-full w-full flex-col items-start justify-center gap-1 pr-14 pl-4 text-left outline-offset-[-3px] hover:bg-accent">
                      <span className="flex max-w-full min-w-0 items-center gap-2.5">
                        <SeverityMark level={f.level} />
                        <span className="truncate text-xs text-muted-foreground">{f.module}{'　'}{visibleOpt(f.campaign) ?? '—'}</span>
                      </span>
                      {f.path ? <PathText path={f.path} className="max-w-full text-[13.5px]" /> : <span className="text-[13.5px] text-muted-foreground">（貼り付けテキスト）</span>}
                      <span className="block max-w-full truncate text-xs text-muted-foreground">{visiblePath(f.detail)}</span>
                    </button>
                    {/* コピーは元の値のまま。読み上げ名だけ表示用 */}
                    {f.path && <Button variant="ghost" size="icon-touch" aria-label={`パスをコピー: ${visiblePath(f.path)}`} onClick={() => copy(f.path!)} className="absolute top-[18px] right-1"><Copy /></Button>}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </Card>
      <FindingSheet finding={detail} onClose={() => setDetail(null)} returnFocus={() => opener.current} />
    </>
  );
}

/** 詳細のシート（承認済み §16-5）。パスと詳細の全文、キャンペーン、モジュール、「パスをコピー」。 */
function FindingSheet({ finding, onClose, returnFocus }: { finding: Finding | null; onClose(): void; returnFocus(): HTMLElement | null }) {
  const copy = useCopy();
  // 閉じるアニメーションの間も内容を残す
  const last = useRef<Finding | null>(null);
  if (finding) last.current = finding;
  const f = finding ?? last.current;
  return (
    <Sheet open={!!finding} onOpenChange={(o) => { if (!o) onClose(); }}>
      {f && (
        <SheetContent
          data-testid="finding-sheet"
          title={<span className="flex items-center gap-2.5"><SeverityMark level={f.level} className="text-[13px]" /><span className="text-sm font-normal text-muted-foreground">{f.module}</span></span>}
          onCloseAutoFocus={(e) => { const el = returnFocus(); if (el?.isConnected) { e.preventDefault(); el.focus(); } }}
          className="pb-[max(env(safe-area-inset-bottom),16px)]"
        >
          <span aria-hidden="true" className={cn('absolute top-5 left-0 h-9 w-1', SEV[f.level].bar)} />
          <div className="flex flex-col gap-4 overflow-y-auto px-4 pt-3">
            {f.path ? <PathText path={f.path} wrap className="text-[15px] leading-snug" /> : <span className="text-muted-foreground">（貼り付けテキスト）</span>}
            <p className="text-sm leading-relaxed">{visiblePath(f.detail)}</p>
            <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1.5 border-t border-border pt-3 text-[13px]">
              <dt className="text-muted-foreground">キャンペーン</dt><dd className="wrap-anywhere">{visibleOpt(f.campaign) ?? '—'}</dd>
              <dt className="text-muted-foreground">モジュール</dt><dd>{f.module}</dd>
            </dl>
            {/* コピーは元の値のまま（表示用の目印を付けない） */}
            {f.path && <Button variant="ink" size="touch" className="w-full" onClick={() => copy(f.path!)}><Copy />パスをコピー</Button>}
          </div>
        </SheetContent>
      )}
    </Sheet>
  );
}

// タブ列（設計書 §10.2）。Radix Tabs（activationMode="manual"、loop）の TabsList。
// ≥640: 収まるタブだけを見せ（列の幅を最後に収まるタブの右端で切る。フェードも矢印ボタンも使わない）、
// 右端に「すべてのタブ 18」（タブ検索）。<640: 44px の横スクロール＋右端に検索ボタン（下からのシート）。
// 収まらないタブも DOM には残す（←→ / Home / End で移れる。フォーカスしたタブは列の中でスクロールして見せる）。
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { useLang } from '@/i18n';
import { TABS, type TabId } from '@/tabs/definitions';
import { TabsList, TabsTrigger } from '@/components/ui/tabs';
import { CountChip } from './CountChip';
import { TabSearch } from './TabSearch';
import type { TabCount } from './tabCounts';

export function TabBar({ active, counts, onPick, mobile }: { active: TabId; counts: Record<TabId, TabCount>; onPick(id: TabId): void; mobile: boolean }) {
  const wrap = useRef<HTMLDivElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const [fit, setFit] = useState<number | undefined>(undefined);
  const { lang, t } = useLang();

  useLayoutEffect(() => {
    const w = wrap.current;
    const l = list.current;
    if (!w || !l || mobile) { setFit(undefined); return; }
    const measure = () => {
      const avail = w.clientWidth + 10; // 列は -ml-2.5 で左の余白に食い込ませている
      let right = 0;
      for (const el of l.querySelectorAll<HTMLElement>('[role=tab]')) {
        const r = el.offsetLeft + el.offsetWidth;
        if (r > avail) break;
        right = r;
      }
      setFit(right || undefined);
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(w);
    return () => ro.disconnect();
  }, [mobile, counts, lang]);

  useEffect(() => {
    list.current?.querySelector<HTMLElement>(`[data-tab="${active}"]`)?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }, [active]);

  return (
    <nav aria-label={t('ui.tabs.nav')} className="flex h-11 items-stretch gap-4 border-b border-border px-6 max-lg:px-4 max-sm:gap-2">
      <div ref={wrap} className="flex min-w-0 flex-1 items-stretch">
        <TabsList
          ref={list}
          aria-label={t('ui.tabs.list')}
          style={fit ? { maxWidth: fit } : undefined}
          className="scrollbar-none relative -ml-2.5 min-w-0 gap-1.5 snap-x snap-mandatory overflow-x-auto max-sm:snap-none"
          onFocus={(e) => (e.target as HTMLElement).scrollIntoView({ block: 'nearest', inline: 'nearest' })}
        >
          {TABS.map((d) => {
            const c = counts[d.id];
            return (
              <TabsTrigger key={d.id} value={d.id} data-tab={d.id} className="snap-start" aria-label={c.max ? t('ui.tabs.trigger_max', { label: t(d.label), n: c.n, max: c.max }) : t('ui.tabs.trigger', { label: t(d.label), n: c.n })}>
                {t(d.label)}
                <CountChip c={c} />
              </TabsTrigger>
            );
          })}
        </TabsList>
      </div>
      <TabSearch active={active} counts={counts} onPick={onPick} mobile={mobile} />
    </nav>
  );
}

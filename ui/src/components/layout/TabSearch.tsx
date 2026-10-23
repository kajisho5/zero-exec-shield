// タブ検索（設計書 §10.2、§16-4）。≥640 は Popover＋Command、<640 は下からのシート＋Command。
// 絞り込みは cmdk のあいまい検索を使わず、NFKC＋小文字化した部分一致（表示名・ID・別名・§番号・キャンペーン）。
// IME 変換中の Enter は cmdk が無視する。
import { useMemo, useRef, useState } from 'react';
import { Check, Search } from 'lucide-react';
import { TABS, type TabDef, type TabId } from '@/tabs/definitions';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Command, CommandEmpty, CommandInput, CommandItem, CommandList } from '@/components/ui/command';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet';
import { CountChip } from './CountChip';
import type { TabCount } from './tabCounts';

const ALIASES: Partial<Record<TabId, string>> = {
  overview: 'overview すべて 全体 sougou',
  actions: 'github workflow ci',
  extensions: 'browser extension chrome 拡張機能',
  'build-hooks': 'build hooks postinstall',
  'model-supply': 'model supply chain pickle safetensors',
  persistence: 'persistence crontab launchd systemd',
  'anti-forensics': 'anti forensics auditd',
  hf: 'hugging face huggingface',
  ebpf: 'ebpf ld_preload rootkit',
  'ai-assistant': 'ai assistant copilot cursor',
  sigstore: 'sigstore sbom cosign',
  pypi: 'python pip',
  mcp: 'model context protocol',
};
const norm = (s: string) => s.normalize('NFKC').toLowerCase();
const HAYSTACK = Object.fromEntries(TABS.map((t) => [t.id, norm([t.label, t.id, ALIASES[t.id] ?? '', ...t.modules, ...t.campaigns].join(' '))])) as Record<TabId, string>;
export const filterTabs = (q: string): TabDef[] => {
  const words = norm(q).trim().split(/\s+/).filter(Boolean);
  return words.length ? TABS.filter((t) => words.every((w) => HAYSTACK[t.id].includes(w))) : TABS;
};

const NOTE = '並びは §7.2 の順で固定。数字は検出件数です。';

function TabSearchList({ active, counts, onPick, touch }: { active: TabId; counts: Record<TabId, TabCount>; onPick(id: TabId): void; touch?: boolean }) {
  const [q, setQ] = useState('');
  const [hl, setHl] = useState<string>(active);
  const list = useMemo(() => filterTabs(q), [q]);
  return (
    <Command shouldFilter={false} loop value={hl} onValueChange={setHl} label="タブを検索" className="min-h-0 flex-1">
      <div className={cn('shrink-0', touch ? 'px-4 pt-4' : 'p-2 pb-0')}>
        <CommandInput
          autoFocus
          value={q}
          onValueChange={(v) => { setQ(v); setHl(filterTabs(v)[0]?.id ?? ''); }}
          placeholder="タブを検索（例: mcp, 永続化）"
          wrapperClassName={touch ? 'h-11' : undefined}
        />
        <p className={cn('text-xs text-muted-foreground', touch ? 'pt-3 pb-1.5' : 'px-1 pt-2 pb-1')}>{NOTE}</p>
      </div>
      <CommandList className={cn(touch ? 'px-2 pb-[max(env(safe-area-inset-bottom),12px)]' : 'max-h-[min(470px,calc(70vh-96px))] p-1.5 pt-0')}>
        <CommandEmpty>該当するタブはありません</CommandEmpty>
        {list.map((t) => {
          const c = counts[t.id];
          return (
            <CommandItem key={t.id} value={t.id} onSelect={() => onPick(t.id)} aria-label={`${t.label}${c.n ? `、検出 ${c.n} 件` : ''}`}
              className={cn(touch ? 'h-11 pr-2 pl-10 text-[15px] after:absolute after:right-0 after:bottom-0 after:left-10 after:h-px after:bg-border data-[selected=true]:after:hidden' : 'h-9 pr-2 pl-9', t.id === active && 'font-semibold')}>
              {t.id === active && <Check aria-hidden="true" strokeWidth={2.5} className={cn('absolute size-4', touch ? 'left-3.5' : 'left-3')} />}
              <span className="min-w-0 flex-1 truncate">{t.label}</span>
              <CountChip c={c} />
            </CommandItem>
          );
        })}
      </CommandList>
    </Command>
  );
}

export function TabSearch({ active, counts, onPick, mobile }: { active: TabId; counts: Record<TabId, TabCount>; onPick(id: TabId): TabId | void; mobile: boolean }) {
  const [open, setOpen] = useState(false);
  // 選んだときはタブにフォーカスを移す（閉じたときの既定はトリガーに戻す）
  const picked = useRef<TabId | null>(null);
  const pick = (id: TabId) => { picked.current = id; setOpen(false); onPick(id); };
  const focusPicked = (e: Event) => {
    if (!picked.current) return;
    e.preventDefault();
    document.querySelector<HTMLElement>(`[role=tab][data-tab="${picked.current}"]`)?.focus();
    picked.current = null;
  };

  if (mobile) {
    return (
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetTrigger asChild>
          <Button variant="outline" size="icon-touch" aria-label={`すべてのタブ（${TABS.length}）を検索`} data-testid="all-tabs" className="my-auto shrink-0"><Search /></Button>
        </SheetTrigger>
        <SheetContent title="すべてのタブ" count={TABS.length} className="h-[min(650px,calc(100dvh-48px))]" onCloseAutoFocus={focusPicked}>
          <TabSearchList active={active} counts={counts} onPick={pick} touch />
        </SheetContent>
      </Sheet>
    );
  }
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="outline" className="my-auto h-[34px] shrink-0 gap-2 px-3.5" data-testid="all-tabs">
          <Search />すべてのタブ<span className="text-xs text-muted-foreground tabular-nums">{TABS.length}</span>
        </Button>
      </PopoverTrigger>
      <PopoverContent aria-label="すべてのタブ" className="flex max-h-[70vh] w-[360px] flex-col" onCloseAutoFocus={focusPicked}>
        <TabSearchList active={active} counts={counts} onPick={pick} />
      </PopoverContent>
    </Popover>
  );
}

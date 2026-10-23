// 集計＝重大度フィルタ（設計書 §10.3、W-6）。サマリカードとフィルタチップを 1 本の ToggleGroup（type="multiple"）に統合。
// 押した区画: 左 3px の帯＋右上のチェック＋語とアイコンを重大度の色に。押していない区画: 鉛筆色＋右上に空の枠。
// 罫の枠だけで塗らない（色は一覧が持つ）。≥640 は 5 区画＋右に SAFE の文、<640 は 3＋2 区画＋SAFE、<360 は 2 列×3 段。
import { Check, CircleCheck, CircleDashed } from 'lucide-react';
import { SEVERITIES, type Severity } from '@/engine';
import { cn } from '@/lib/utils';
import { SEV } from '@/components/severity/severity';
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group';

function SafeStatement({ clear, total, compact }: { clear: number; total: number; compact?: boolean }) {
  // チェックを 1 つも実行していない（未投入・取り込みや貼り付けだけ）ときは、緑の「✓ 0 / 0」で安全に見せない。無彩色の「—」
  const none = total === 0;
  const Icon = none ? CircleDashed : CircleCheck;
  return (
    <div data-testid="card-SAFE" data-safe={none ? 'none' : 'run'} className={cn('flex min-w-0 gap-2', compact ? 'flex-col justify-center gap-0.5 px-3 py-2' : 'items-start')}>
      <span className={cn('flex items-center gap-1.5', compact ? 'text-[13px]' : 'pt-0.5 text-sm')}>
        <Icon aria-hidden="true" strokeWidth={2.25} className={cn('shrink-0', none ? 'text-muted-foreground' : 'text-safe', compact ? 'size-[13px]' : 'size-[15px]')} />
        {none
          ? <span className={cn('tabular-nums', compact ? 'font-semibold' : 'text-muted-foreground')}>—{!compact && <span> チェック非該当</span>}</span>
          : <span className="tabular-nums"><b className="font-semibold">{clear}</b> <span className={compact ? 'font-semibold' : 'text-muted-foreground'}>/ {total}</span>{!compact && <span className="text-muted-foreground"> チェック非該当</span>}</span>}
      </span>
      {compact && <span className="text-[11.5px] text-muted-foreground">チェック非該当</span>}
    </div>
  );
}

export function Tally({ counts, active, onToggle, safe, mobile }: {
  counts: Record<Severity, number>; active: Set<Severity>; onToggle(s: Severity): void; safe: { clear: number; total: number }; mobile: boolean;
}) {
  const value = SEVERITIES.filter((s) => active.has(s));
  const change = (next: string[]) => {
    for (const s of SEVERITIES) if (next.includes(s) !== active.has(s)) onToggle(s);
  };
  const seg = (s: Severity) => {
    const on = active.has(s);
    const st = SEV[s];
    const Icon = st.icon;
    return (
      <ToggleGroupItem key={s} value={s} data-testid={`filter-${s}`} aria-label={`${s} ${counts[s]} 件を表示`}
        className={cn('relative flex min-w-0 flex-col items-start justify-center gap-1 border-border text-left outline-offset-[-3px] hover:bg-accent', mobile ? 'h-14 px-3' : 'h-16 px-4')}>
        {on && <span aria-hidden="true" className={cn('absolute inset-y-0 left-0 w-[3px]', st.bar)} />}
        <span data-testid={`count-${s}`} className={cn('leading-none font-semibold tabular-nums', mobile ? 'text-[19px]' : 'text-[21px]', on ? 'text-foreground' : 'text-muted-foreground')}>{counts[s]}</span>
        <span className={cn('flex items-center gap-[5px] font-semibold', mobile ? 'text-[11.5px]' : 'text-xs', on ? st.fg : 'text-muted-foreground')}>
          <Icon aria-hidden="true" strokeWidth={2.25} className="size-3 shrink-0" />{s}
        </span>
        <span aria-hidden="true" className={cn('absolute top-2.5', mobile ? 'right-2.5' : 'right-3.5')}>
          {on ? <Check strokeWidth={2.5} className={cn('size-3.5', st.fg)} /> : <span className="block size-3.5 rounded-xs border-[1.25px] border-input" />}
        </span>
      </ToggleGroupItem>
    );
  };

  if (mobile) {
    return (
      <ToggleGroup type="multiple" value={value} onValueChange={change} aria-label="重大度で絞り込み"
        className="grid grid-cols-3 overflow-hidden rounded-md border border-border max-[359px]:grid-cols-2 [&>*]:border-b [&>*]:border-l [&>*]:-mb-px [&>*]:-ml-px">
        {SEVERITIES.map(seg)}
        <SafeStatement {...safe} compact />
      </ToggleGroup>
    );
  }
  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
      <ToggleGroup type="multiple" value={value} onValueChange={change} aria-label="重大度で絞り込み"
        className="grid w-full max-w-[750px] grid-cols-5 overflow-hidden rounded-md border border-border [&>*+*]:border-l">
        {SEVERITIES.map(seg)}
      </ToggleGroup>
      <div className="flex flex-col gap-0.5">
        <SafeStatement {...safe} />
        <span className="pl-[23px] text-xs text-muted-foreground">ブラウザで判定できる範囲のみ</span>
      </div>
    </div>
  );
}

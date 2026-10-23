// タブの件数: 最大の重大度の淡色地に、その文字色の数字（12px の 600、角丸 3）。0 件なら出さない（§10.2）。
import { cn } from '@/lib/utils';
import { SEV } from '@/components/severity/severity';
import type { TabCount } from './tabCounts';

export function CountChip({ c, className }: { c: TabCount; className?: string }) {
  if (!c.n) return null;
  const s = c.max ? SEV[c.max] : null;
  return <span aria-hidden="true" className={cn('rounded-sm px-[5px] text-xs leading-[18px] font-semibold tabular-nums', s ? `${s.tint} ${s.fg}` : 'text-muted-foreground', className)}>{c.n}</span>;
}

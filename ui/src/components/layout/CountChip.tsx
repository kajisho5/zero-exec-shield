// Tab count: the number in the text color of the highest severity on its tint (12px, 600, radius 3). Not shown for 0 (§10.2).
import { cn } from '@/lib/utils';
import { SEV } from '@/components/severity/severity';
import type { TabCount } from './tabCounts';

export function CountChip({ c, className }: { c: TabCount; className?: string }) {
  if (!c.n) return null;
  const s = c.max ? SEV[c.max] : null;
  return <span aria-hidden="true" className={cn('rounded-sm px-[5px] text-xs leading-[18px] font-semibold tabular-nums', s ? `${s.tint} ${s.fg}` : 'text-muted-foreground', className)}>{c.n}</span>;
}

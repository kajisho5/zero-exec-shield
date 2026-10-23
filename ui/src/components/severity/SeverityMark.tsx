// Gutter mark: shape + word in the severity color. No border (design doc §9).
import { cn } from '@/lib/utils';
import type { DisplaySeverity } from '@/engine';
import { SEV } from './severity';

export function SeverityMark({ level, className, size = 'md' }: { level: DisplaySeverity; className?: string; size?: 'sm' | 'md' }) {
  const s = SEV[level];
  const Icon = s.icon;
  return (
    <span data-severity={level} className={cn('inline-flex items-center gap-1.5 font-semibold whitespace-nowrap', size === 'sm' ? 'text-[11.5px]' : 'text-xs', s.fg, className)}>
      <Icon aria-hidden="true" strokeWidth={2.25} className="size-[13px] shrink-0" />
      {level}
    </span>
  );
}

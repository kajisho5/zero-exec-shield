// Severity tag: tint ground + text in the severity color, radius 3. Not a pill, letter spacing 0 (design doc §9, A-14).
import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';
import type { DisplaySeverity } from '@/engine';
import { SEV } from './severity';

export function SeverityTag({ level, children, className, icon = true }: { level: DisplaySeverity; children?: ReactNode; className?: string; icon?: boolean }) {
  const s = SEV[level];
  const Icon = s.icon;
  return (
    <span data-severity={level} className={cn('inline-flex h-[22px] shrink-0 items-center gap-1 rounded-sm px-[7px] text-xs font-medium whitespace-nowrap', s.tint, s.fg, className)}>
      {icon && <Icon aria-hidden="true" strokeWidth={2.25} className="size-3 shrink-0" />}
      {children ?? level}
    </span>
  );
}

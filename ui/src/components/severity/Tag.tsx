// Neutral tag: rule border, pencil-colored text, radius 3. For accompanying information that is not a severity ("existence only, content hidden" etc.).
import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

export function Tag({ children, className, icon, mono }: { children: ReactNode; className?: string; icon?: ReactNode; mono?: boolean }) {
  return (
    <span className={cn('inline-flex h-[22px] shrink-0 items-center gap-1 rounded-sm border border-border px-[7px] text-xs font-medium whitespace-nowrap text-muted-foreground [&_svg]:size-3 [&_svg]:shrink-0', mono && 'font-mono', className)}>
      {icon}
      {children}
    </span>
  );
}

// Stamp (violet ink): a double border of 1.5px outer + 0.75px inner, radius 2. A mark that only shows that a signature file exists.
// No green, teal, ink or check-shaped icons (the L3 rule of design doc §5.3, C-10).
import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

export function Stamp({ children, size = 'md', className, ...rest }: { children: ReactNode; size?: 'sm' | 'md'; className?: string } & React.HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn(
        'relative inline-flex shrink-0 items-center rounded-xs border-[1.5px] border-signed font-semibold whitespace-nowrap text-signed',
        'before:pointer-events-none before:absolute before:inset-[1.5px] before:rounded-[1px] before:border-[0.75px] before:border-signed',
        size === 'sm' ? 'h-6 px-2 text-[11.5px]' : 'h-[30px] px-2.5 text-[13px]',
        className,
      )}
      {...rest}
    >
      {children}
    </span>
  );
}

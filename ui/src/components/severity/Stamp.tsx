// 押印（紫インク）: 外枠 1.5px＋内枠 0.75px の二重枠、角丸 2。署名ファイルが「ある」ことだけを示す印。
// 緑・ティール・墨・チェック形のアイコンは使わない（設計書 §5.3 の L3 の規則、C-10）。
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

// 無彩色のタグ: 罫の枠、鉛筆色の文字、角丸 3。重大度ではない付帯情報（「存在のみ・内容非表示」など）に使う。
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

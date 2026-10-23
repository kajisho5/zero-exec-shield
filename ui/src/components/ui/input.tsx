// shadcn/ui new-york-v4 の input を手で取り込み、「検疫台」に書き換えたもの（MIT。NOTICE を参照）。
// 凹みの地、縁（3:1 以上）の枠、角丸 6。左にアイコンを置ける。フォーカスは全体共通の墨の輪郭。
import type * as React from 'react';
import { cn } from '@/lib/utils';

function Input({ className, icon, ...props }: React.ComponentProps<'input'> & { icon?: React.ReactNode }) {
  return (
    <label data-slot="input-wrapper" className={cn('flex h-9 min-w-0 items-center gap-2 rounded-lg border border-input bg-muted px-3 text-muted-foreground has-[input:focus-visible]:outline-2 has-[input:focus-visible]:outline-offset-2 has-[input:focus-visible]:outline-foreground pointer-coarse:h-11', className)}>
      {icon}
      <input data-slot="input" className="h-full w-full min-w-0 bg-transparent text-sm text-foreground outline-none" {...props} />
    </label>
  );
}

export { Input };

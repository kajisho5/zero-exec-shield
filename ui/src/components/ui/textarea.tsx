// shadcn/ui new-york-v4 の textarea を手で取り込み、「検疫台」に書き換えたもの（MIT。NOTICE を参照）。
import type * as React from 'react';
import { cn } from '@/lib/utils';

function Textarea({ className, ...props }: React.ComponentProps<'textarea'>) {
  return <textarea data-slot="textarea" className={cn('w-full min-w-0 resize-none rounded-lg border border-input bg-muted px-3 py-2 text-[13.5px] leading-normal text-foreground', className)} {...props} />;
}

export { Textarea };

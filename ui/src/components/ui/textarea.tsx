// The shadcn/ui new-york-v4 textarea, imported by hand and rewritten for the "quarantine bench" (MIT; see NOTICE).
import type * as React from 'react';
import { cn } from '@/lib/utils';

function Textarea({ className, ...props }: React.ComponentProps<'textarea'>) {
  return <textarea data-slot="textarea" className={cn('w-full min-w-0 resize-none rounded-lg border border-input bg-muted px-3 py-2 text-[13.5px] leading-normal text-foreground', className)} {...props} />;
}

export { Textarea };

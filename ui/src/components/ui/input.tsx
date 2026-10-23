// The shadcn/ui new-york-v4 input, imported by hand and rewritten for the "quarantine bench" (MIT; see NOTICE).
// Well ground, edge border (3:1 or more), radius 6. An icon can be placed on the left. Focus uses the global ink outline.
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

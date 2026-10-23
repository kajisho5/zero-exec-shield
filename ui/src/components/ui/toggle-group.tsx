// The shadcn/ui new-york-v4 toggle-group, imported by hand and rewritten for the "quarantine bench" tally (severity filter)
// (MIT; see NOTICE). Changes: toggleVariants and the spacing mechanism are removed; the caller (Tally) owns the look.
import type * as React from 'react';
import * as ToggleGroupPrimitive from '@radix-ui/react-toggle-group';
import { cn } from '@/lib/utils';

function ToggleGroup({ className, ...props }: React.ComponentProps<typeof ToggleGroupPrimitive.Root>) {
  return <ToggleGroupPrimitive.Root data-slot="toggle-group" className={cn('flex', className)} {...props} />;
}

function ToggleGroupItem({ className, ...props }: React.ComponentProps<typeof ToggleGroupPrimitive.Item>) {
  return <ToggleGroupPrimitive.Item data-slot="toggle-group-item" className={cn('cursor-pointer', className)} {...props} />;
}

export { ToggleGroup, ToggleGroupItem };

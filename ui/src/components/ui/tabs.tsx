// The shadcn/ui new-york-v4 tabs, imported by hand and rewritten for the "quarantine bench" (MIT; see NOTICE).
// Changes: line style only. Selected is ink 600 + a 2px ink line below; others are pencil 500 (ink on hover).
// Callers use activationMode="manual" (move with ←→, select with Enter / Space).
import type * as React from 'react';
import * as TabsPrimitive from '@radix-ui/react-tabs';
import { cn } from '@/lib/utils';

function Tabs(props: React.ComponentProps<typeof TabsPrimitive.Root>) {
  return <TabsPrimitive.Root data-slot="tabs" {...props} />;
}

function TabsList({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.List>) {
  return <TabsPrimitive.List data-slot="tabs-list" className={cn('flex items-stretch', className)} {...props} />;
}

function TabsTrigger({ className, onMouseDown, ...props }: React.ComponentProps<typeof TabsPrimitive.Trigger>) {
  return (
    <TabsPrimitive.Trigger
      data-slot="tabs-trigger"
      // Radix calls focus() on mousedown. When the first interaction is a mouse, Chromium treats it as keyboard-originated and
      // shows the focus outline, so focus first with focusVisible: false (the focus() of Radix then does nothing)
      onMouseDown={(e) => { onMouseDown?.(e); if (e.button === 0 && !e.ctrlKey) e.currentTarget.focus({ focusVisible: false } as FocusOptions); }}
      className={cn(
        'relative flex shrink-0 cursor-pointer items-center gap-1.5 px-2.5 text-sm font-medium whitespace-nowrap text-muted-foreground outline-offset-[-4px] hover:text-foreground',
        'after:absolute after:inset-x-2.5 after:bottom-0 after:h-0.5 after:bg-foreground after:opacity-0 data-[state=active]:font-semibold data-[state=active]:text-foreground data-[state=active]:after:opacity-100',
        className,
      )}
      {...props}
    />
  );
}

function TabsContent({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Content>) {
  return <TabsPrimitive.Content data-slot="tabs-content" className={className} {...props} />;
}

export { Tabs, TabsContent, TabsList, TabsTrigger };

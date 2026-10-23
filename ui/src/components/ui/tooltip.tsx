// The shadcn/ui new-york-v4 tooltip, imported by hand and rewritten for the "quarantine bench" (MIT; see NOTICE).
// Changes: bench-colored text on an ink ground, radius 4, no arrow, no zoom (400ms delay, 80ms fade only. §7).
import type * as React from 'react';
import * as TooltipPrimitive from '@radix-ui/react-tooltip';
import { cn } from '@/lib/utils';

function TooltipProvider({ delayDuration = 400, ...props }: React.ComponentProps<typeof TooltipPrimitive.Provider>) {
  return <TooltipPrimitive.Provider data-slot="tooltip-provider" delayDuration={delayDuration} {...props} />;
}

function Tooltip(props: React.ComponentProps<typeof TooltipPrimitive.Root>) {
  return <TooltipPrimitive.Root data-slot="tooltip" {...props} />;
}

function TooltipTrigger(props: React.ComponentProps<typeof TooltipPrimitive.Trigger>) {
  return <TooltipPrimitive.Trigger data-slot="tooltip-trigger" {...props} />;
}

function TooltipContent({ className, sideOffset = 6, ...props }: React.ComponentProps<typeof TooltipPrimitive.Content>) {
  return (
    <TooltipPrimitive.Portal>
      <TooltipPrimitive.Content
        data-slot="tooltip-content"
        sideOffset={sideOffset}
        collisionPadding={8}
        className={cn('z-50 max-w-72 rounded-md bg-primary px-2.5 py-1 text-xs leading-relaxed font-medium text-primary-foreground shadow-lift data-[state=closed]:animate-fade-out data-[state=delayed-open]:animate-tip-in data-[state=instant-open]:animate-tip-in', className)}
        {...props}
      />
    </TooltipPrimitive.Portal>
  );
}

/** The common form: make the child the trigger and attach a string tooltip. */
function Tip({ label, side, children }: { label: React.ReactNode; side?: 'top' | 'right' | 'bottom' | 'left'; children: React.ReactElement }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>{children}</TooltipTrigger>
      <TooltipContent side={side}>{label}</TooltipContent>
    </Tooltip>
  );
}

export { Tip, Tooltip, TooltipContent, TooltipProvider, TooltipTrigger };

// The shadcn/ui new-york-v4 command (cmdk), imported by hand and rewritten for the "quarantine bench" tab search (MIT; see NOTICE).
// Changes: the input has the well ground and an edge border. Items use the selected-row ground + an ink band on the left. CommandDialog is not used (placed in a Popover / Sheet).
import type * as React from 'react';
import { Command as CommandPrimitive } from 'cmdk';
import { Search } from 'lucide-react';
import { cn } from '@/lib/utils';

function Command({ className, ...props }: React.ComponentProps<typeof CommandPrimitive>) {
  return <CommandPrimitive data-slot="command" className={cn('flex min-h-0 w-full flex-col text-popover-foreground', className)} {...props} />;
}

function CommandInput({ className, wrapperClassName, ...props }: React.ComponentProps<typeof CommandPrimitive.Input> & { wrapperClassName?: string }) {
  return (
    <div data-slot="command-input-wrapper" className={cn('flex h-9 items-center gap-2 rounded-lg border border-input bg-muted px-3 has-[input:focus-visible]:outline-2 has-[input:focus-visible]:outline-offset-2 has-[input:focus-visible]:outline-foreground', wrapperClassName)}>
      <Search aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
      <CommandPrimitive.Input data-slot="command-input" className={cn('h-full w-full min-w-0 bg-transparent text-sm outline-none', className)} {...props} />
    </div>
  );
}

function CommandList({ className, ...props }: React.ComponentProps<typeof CommandPrimitive.List>) {
  return <CommandPrimitive.List data-slot="command-list" className={cn('min-h-0 scroll-py-1 overflow-x-hidden overflow-y-auto overscroll-contain', className)} {...props} />;
}

function CommandEmpty({ className, ...props }: React.ComponentProps<typeof CommandPrimitive.Empty>) {
  return <CommandPrimitive.Empty data-slot="command-empty" className={cn('px-3 py-6 text-center text-sm text-muted-foreground', className)} {...props} />;
}

function CommandItem({ className, ...props }: React.ComponentProps<typeof CommandPrimitive.Item>) {
  return (
    <CommandPrimitive.Item
      data-slot="command-item"
      className={cn(
        "relative flex cursor-pointer items-center gap-2 rounded-md text-sm outline-none select-none data-[selected=true]:bg-accent [&_svg]:pointer-events-none [&_svg]:shrink-0",
        "before:absolute before:top-1.5 before:bottom-1.5 before:left-0 before:w-[3px] before:bg-foreground before:opacity-0 data-[selected=true]:before:opacity-100",
        className,
      )}
      {...props}
    />
  );
}

export { Command, CommandEmpty, CommandInput, CommandItem, CommandList };

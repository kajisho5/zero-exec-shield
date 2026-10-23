// The shadcn/ui new-york-v4 native-select, imported by hand and rewritten for the "quarantine bench" (MIT; see NOTICE).
// Radix Select is not used because it injects <style> at runtime (design doc §4.2).
import type * as React from 'react';
import { ChevronDown } from 'lucide-react';
import { cn } from '@/lib/utils';

function NativeSelect({ className, wrapperClassName, ...props }: React.ComponentProps<'select'> & { wrapperClassName?: string }) {
  return (
    <div data-slot="native-select-wrapper" className={cn('relative min-w-0', wrapperClassName)}>
      <select
        data-slot="native-select"
        className={cn('h-9 w-full min-w-0 cursor-pointer appearance-none truncate rounded-lg border border-input bg-muted py-0 pr-9 pl-3 text-sm text-foreground pointer-coarse:h-11', className)}
        {...props}
      />
      <ChevronDown aria-hidden="true" className="pointer-events-none absolute top-1/2 right-3 size-4 -translate-y-1/2 text-muted-foreground" />
    </div>
  );
}

function NativeSelectOption(props: React.ComponentProps<'option'>) {
  return <option data-slot="native-select-option" className="bg-popover text-foreground" {...props} />;
}

export { NativeSelect, NativeSelectOption };

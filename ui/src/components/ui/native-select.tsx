// shadcn/ui new-york-v4 の native-select を手で取り込み、「検疫台」に書き換えたもの（MIT。NOTICE を参照）。
// Radix Select は実行時に <style> を差し込むため使わない（設計書 §4.2）。
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

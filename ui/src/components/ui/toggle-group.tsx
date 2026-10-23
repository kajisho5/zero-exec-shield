// shadcn/ui new-york-v4 の toggle-group を手で取り込み、「検疫台」の集計（重大度フィルタ）用に書き換えたもの
// （MIT。NOTICE を参照）。変更点: toggleVariants とスペーシングの仕組みを外し、見た目は呼び出し側（Tally）が持つ。
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

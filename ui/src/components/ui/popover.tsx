// shadcn/ui new-york-v4 の popover を手で取り込み、「検疫台」に書き換えたもの（MIT。NOTICE を参照）。
// 変更点: 浮きの地、罫、角丸 6、影は浮くものだけ。出入りは 120ms のフェードのみ（ズームしない。§7）。
import type * as React from 'react';
import * as PopoverPrimitive from '@radix-ui/react-popover';
import { cn } from '@/lib/utils';

function Popover(props: React.ComponentProps<typeof PopoverPrimitive.Root>) {
  return <PopoverPrimitive.Root data-slot="popover" {...props} />;
}

function PopoverTrigger(props: React.ComponentProps<typeof PopoverPrimitive.Trigger>) {
  return <PopoverPrimitive.Trigger data-slot="popover-trigger" {...props} />;
}

function PopoverContent({ className, align = 'end', sideOffset = 6, ...props }: React.ComponentProps<typeof PopoverPrimitive.Content>) {
  return (
    <PopoverPrimitive.Portal>
      <PopoverPrimitive.Content
        data-slot="popover-content"
        align={align}
        sideOffset={sideOffset}
        collisionPadding={8}
        className={cn('z-50 rounded-lg border border-border bg-popover text-popover-foreground shadow-lift outline-none data-[state=open]:animate-fade-in', className)}
        {...props}
      />
    </PopoverPrimitive.Portal>
  );
}

export { Popover, PopoverContent, PopoverTrigger };

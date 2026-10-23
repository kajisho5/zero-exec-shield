// shadcn/ui new-york-v4 の tooltip を手で取り込み、「検疫台」に書き換えたもの（MIT。NOTICE を参照）。
// 変更点: 墨の地に作業台色の文字、角丸 4、矢印なし、ズームなし（遅延 400ms・80ms のフェードのみ。§7）。
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

/** よく使う形: 子をトリガーにして、文字列のツールチップを付ける。 */
function Tip({ label, side, children }: { label: React.ReactNode; side?: 'top' | 'right' | 'bottom' | 'left'; children: React.ReactElement }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>{children}</TooltipTrigger>
      <TooltipContent side={side}>{label}</TooltipContent>
    </Tooltip>
  );
}

export { Tip, Tooltip, TooltipContent, TooltipProvider, TooltipTrigger };

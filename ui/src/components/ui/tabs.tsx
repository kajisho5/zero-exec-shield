// shadcn/ui new-york-v4 の tabs を手で取り込み、「検疫台」に書き換えたもの（MIT。NOTICE を参照）。
// 変更点: line 型だけ。選択中は墨の 600＋下に 2px の墨の線、それ以外は鉛筆の 500（hover で墨）。
// 呼び出し側は activationMode="manual"（←→ で移動、Enter / Space で選ぶ）で使う。
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
      // Radix は mousedown で focus() を呼ぶ。最初の操作がマウスのときに Chromium がそれをキーボード由来とみなして
      // フォーカスの輪郭を出すので、先に focusVisible: false でフォーカスしておく（Radix の focus() は何もしない）
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

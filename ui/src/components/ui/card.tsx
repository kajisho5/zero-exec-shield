// shadcn/ui new-york-v4 の card を手で取り込み、「検疫台」の台紙に書き換えたもの（MIT。NOTICE を参照）。
// 台紙は「読む対象」だけに使う（検体票・検出一覧・SkillPact の報告・各ビューア）。角丸 4、罫 1px、影なし。
import type * as React from 'react';
import { cn } from '@/lib/utils';

function Card({ className, ...props }: React.ComponentProps<'section'>) {
  return <section data-slot="card" className={cn('min-w-0 rounded-md border border-border bg-card text-card-foreground', className)} {...props} />;
}

export { Card };

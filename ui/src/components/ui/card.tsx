// The shadcn/ui new-york-v4 card, imported by hand and rewritten as the "quarantine bench" sheet (MIT; see NOTICE).
// Sheets are used only for "things to read" (sample record, findings list, SkillPact report, each viewer). Radius 4, 1px rule, no shadows.
import type * as React from 'react';
import { cn } from '@/lib/utils';

function Card({ className, ...props }: React.ComponentProps<'section'>) {
  return <section data-slot="card" className={cn('min-w-0 rounded-md border border-border bg-card text-card-foreground', className)} {...props} />;
}

export { Card };

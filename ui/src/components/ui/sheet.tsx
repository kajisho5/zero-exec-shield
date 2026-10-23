// The shadcn/ui new-york-v4 sheet (Radix Dialog), imported by hand and rewritten as the "bottom sheet" of the "quarantine bench"
// (MIT; see NOTICE). Changes: bottom only, raised ground, top corner radius 14, a grabber, 180ms translateY only.
// The background scroll lock is done by the CSP-compatible module of react-remove-scroll (src/lib/remove-scroll-csp.tsx).
import type * as React from 'react';
import * as SheetPrimitive from '@radix-ui/react-dialog';
import { X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useLang } from '@/i18n';
import { Button } from './button';

function Sheet(props: React.ComponentProps<typeof SheetPrimitive.Root>) {
  return <SheetPrimitive.Root data-slot="sheet" {...props} />;
}

function SheetTrigger(props: React.ComponentProps<typeof SheetPrimitive.Trigger>) {
  return <SheetPrimitive.Trigger data-slot="sheet-trigger" {...props} />;
}

function SheetClose(props: React.ComponentProps<typeof SheetPrimitive.Close>) {
  return <SheetPrimitive.Close data-slot="sheet-close" {...props} />;
}

function SheetContent({ className, children, title, count, description, ...props }: Omit<React.ComponentProps<typeof SheetPrimitive.Content>, 'title'> & {
  title: React.ReactNode;
  /** Count to the right of the title (pencil) */
  count?: React.ReactNode;
  /** Supplementary text below the title. When absent, no accessible description is attached */
  description?: React.ReactNode;
}) {
  const { t } = useLang();
  return (
    <SheetPrimitive.Portal>
      <SheetPrimitive.Overlay data-slot="sheet-overlay" className="fixed inset-0 z-50 bg-scrim data-[state=closed]:animate-fade-out data-[state=open]:animate-fade-in" />
      <SheetPrimitive.Content
        data-slot="sheet-content"
        className={cn(
          'fixed inset-x-0 bottom-0 z-50 flex max-h-[calc(100dvh-48px)] flex-col rounded-t-2xl border border-b-0 border-border bg-popover text-popover-foreground shadow-lift outline-none data-[state=closed]:animate-sheet-out data-[state=open]:animate-sheet-in',
          className,
        )}
        {...(description ? {} : { 'aria-describedby': undefined })}
        {...props}
      >
        <div aria-hidden="true" className="mx-auto mt-2 h-1 w-9 shrink-0 rounded-full bg-input" />
        <div className="flex shrink-0 items-center gap-2 px-4 pt-2">
          <SheetPrimitive.Title data-slot="sheet-title" className="flex min-w-0 flex-1 items-baseline gap-2 text-lg font-semibold">
            {title}
            {count != null && <span className="text-[13px] font-medium text-muted-foreground tabular-nums">{count}</span>}
          </SheetPrimitive.Title>
          <SheetPrimitive.Close asChild>
            <Button variant="ghost" size="icon-touch" aria-label={t('ui.sheet.close')}><X /></Button>
          </SheetPrimitive.Close>
        </div>
        {description && <SheetPrimitive.Description className="px-4 text-xs text-muted-foreground">{description}</SheetPrimitive.Description>}
        {children}
      </SheetPrimitive.Content>
    </SheetPrimitive.Portal>
  );
}

export { Sheet, SheetClose, SheetContent, SheetTrigger };

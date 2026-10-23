// The shadcn/ui new-york-v4 button, imported by hand and rewritten to fit the "quarantine bench" (MIT; see NOTICE).
// Changes: only 3 variants, ink (ink fill) / outline / ghost. Radius 6. disabled is not faded by opacity but uses a rule border and pencil color.
// Height 36 (sm 30-32), 44 on touch devices (pointer: coarse).
import type * as React from 'react';
import { Slot } from '@radix-ui/react-slot';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const buttonVariants = cva(
  "inline-flex shrink-0 cursor-pointer items-center justify-center gap-2 rounded-lg text-sm font-medium whitespace-nowrap select-none disabled:cursor-not-allowed [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  {
    variants: {
      variant: {
        ink: 'bg-primary text-primary-foreground hover:bg-primary/90 disabled:border disabled:border-border disabled:bg-transparent disabled:text-muted-foreground',
        outline: 'border border-input text-foreground hover:bg-accent disabled:border-border disabled:text-muted-foreground disabled:hover:bg-transparent',
        ghost: 'text-foreground hover:bg-accent disabled:text-muted-foreground disabled:hover:bg-transparent',
      },
      size: {
        default: 'h-9 px-3.5 pointer-coarse:h-11',
        sm: 'h-8 px-2.5 text-[13px] pointer-coarse:h-11',
        icon: 'size-9 pointer-coarse:size-11',
        'icon-sm': 'size-8 pointer-coarse:size-11',
        touch: 'h-11 px-3.5',
        'icon-touch': 'size-11',
      },
    },
    defaultVariants: { variant: 'outline', size: 'default' },
  },
);

function Button({ className, variant, size, asChild = false, type = 'button', ...props }: React.ComponentProps<'button'> & VariantProps<typeof buttonVariants> & { asChild?: boolean }) {
  const Comp = asChild ? Slot : 'button';
  return <Comp data-slot="button" type={asChild ? undefined : type} className={cn(buttonVariants({ variant, size, className }))} {...props} />;
}

export { Button, buttonVariants };

// Mapping table for severity display (design doc §5.3). Always shows shape (lucide) + word + color together; never distinguishes by color alone.
// Class names are all written as literal strings so Tailwind can pick them up statically.
import { CircleAlert, CircleCheck, Diamond, Info, OctagonAlert, TriangleAlert, type LucideIcon } from 'lucide-react';
import type { DisplaySeverity } from '@/engine';

export interface SevStyle {
  icon: LucideIcon;
  /** Color of text, icon and band */
  fg: string;
  /** Tint ground */
  tint: string;
  /** Band on the left edge */
  bar: string;
  /** Fill (the SkillPact undeclared pill) */
  solid: string;
}

export const SEV: Record<DisplaySeverity, SevStyle> = {
  CRITICAL: { icon: OctagonAlert, fg: 'text-critical', tint: 'bg-critical-tint', bar: 'bg-critical', solid: 'bg-critical-solid text-critical-solid-fg' },
  HIGH: { icon: TriangleAlert, fg: 'text-high', tint: 'bg-high-tint', bar: 'bg-high', solid: 'bg-high-solid text-high-solid-fg' },
  MEDIUM: { icon: CircleAlert, fg: 'text-medium', tint: 'bg-medium-tint', bar: 'bg-medium', solid: 'bg-medium-solid text-medium-solid-fg' },
  LOW: { icon: Diamond, fg: 'text-low', tint: 'bg-low-tint', bar: 'bg-low', solid: 'bg-low-solid text-low-solid-fg' },
  INFO: { icon: Info, fg: 'text-info', tint: 'bg-info-tint', bar: 'bg-info', solid: 'bg-info-solid text-info-solid-fg' },
  SAFE: { icon: CircleCheck, fg: 'text-safe', tint: 'bg-safe-tint', bar: 'bg-safe', solid: 'bg-safe-solid text-safe-solid-fg' },
};

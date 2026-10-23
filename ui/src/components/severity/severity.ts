// 重大度の表示の対応表（設計書 §5.3）。形（lucide）＋語＋色を必ず併記し、色だけで区別しない。
// クラス名は Tailwind が静的に拾えるよう、すべて文字列のまま書く。
import { CircleAlert, CircleCheck, Diamond, Info, OctagonAlert, TriangleAlert, type LucideIcon } from 'lucide-react';
import type { DisplaySeverity } from '@/engine';

export interface SevStyle {
  icon: LucideIcon;
  /** 文字・アイコン・帯の色 */
  fg: string;
  /** 淡色地 */
  tint: string;
  /** 左端の帯 */
  bar: string;
  /** 塗り（SkillPact の未宣言のピル） */
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

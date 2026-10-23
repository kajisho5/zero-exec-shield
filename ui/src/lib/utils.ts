import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

/** shadcn/ui の cn()。clsx で組み立て、tailwind-merge で同じ性質のクラスの後勝ちを解決する。 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

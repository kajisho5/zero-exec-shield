import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

/** cn() of shadcn/ui. Builds with clsx and resolves conflicting classes of the same kind with tailwind-merge (last wins). */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

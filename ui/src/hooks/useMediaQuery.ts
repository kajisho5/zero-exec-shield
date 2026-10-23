import { useSyncExternalStore } from 'react';

/** Subscribes to the result of matchMedia. Used only for boundaries that split rendering (such as the card-style list below 640). */
export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (cb) => {
      const m = window.matchMedia(query);
      m.addEventListener('change', cb);
      return () => m.removeEventListener('change', cb);
    },
    () => window.matchMedia(query).matches,
  );
}

/** "<640" of design doc §8.2. */
export const useIsMobile = () => !useMediaQuery('(min-width: 640px)');

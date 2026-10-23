import { useSyncExternalStore } from 'react';

/** matchMedia の結果を購読する。描画を分ける境界（<640 のカード型の一覧など）にだけ使う。 */
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

/** 設計書 §8.2 の「<640」。 */
export const useIsMobile = () => !useMediaQuery('(min-width: 640px)');

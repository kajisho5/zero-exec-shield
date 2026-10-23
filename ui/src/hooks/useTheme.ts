// テーマ: ダーク / ライト / システム（設計書 §5.4、§16-1）。
// 既定は「システム」で、OS がライトを指定しているときだけライト、それ以外（指定なしを含む）はダーク。
// 選んだ値は localStorage の zes-theme に保存する。file:// やプライベートモードで localStorage が使えない
// ときは例外を握りつぶし、保存せずに動かす（表示は OS の設定に従う）。
import { useCallback, useSyncExternalStore } from 'react';
import { useMediaQuery } from './useMediaQuery';

export type ThemePref = 'dark' | 'light' | 'system';
const KEY = 'zes-theme';
const listeners = new Set<() => void>();

function read(): ThemePref {
  try {
    const v = window.localStorage.getItem(KEY);
    return v === 'dark' || v === 'light' ? v : 'system';
  } catch {
    return 'system';
  }
}

let current: ThemePref = typeof window === 'undefined' ? 'system' : read();

/** html に .dark / .light を付ける（system のときはどちらも外し、CSS の prefers-color-scheme に任せる）。 */
export function applyTheme(pref: ThemePref = current) {
  const c = document.documentElement.classList;
  c.toggle('dark', pref === 'dark');
  c.toggle('light', pref === 'light');
}

function set(pref: ThemePref) {
  current = pref;
  try {
    if (pref === 'system') window.localStorage.removeItem(KEY);
    else window.localStorage.setItem(KEY, pref);
  } catch {
    // 保存できなくても、このページを開いている間は切り替わる
  }
  applyTheme(pref);
  listeners.forEach((l) => l());
}

export function useTheme() {
  const pref = useSyncExternalStore((cb) => { listeners.add(cb); return () => listeners.delete(cb); }, () => current);
  const osLight = useMediaQuery('(prefers-color-scheme: light)');
  const resolved: 'dark' | 'light' = pref === 'system' ? (osLight ? 'light' : 'dark') : pref;
  return { pref, resolved, setTheme: useCallback((p: ThemePref) => set(p), []) };
}

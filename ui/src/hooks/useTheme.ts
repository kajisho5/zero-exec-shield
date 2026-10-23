// Theme: dark / light / system (design doc §5.4, §16-1).
// The default is "system": light only when the OS asks for light, dark otherwise (including no preference).
// The chosen value is saved in zes-theme in localStorage. When localStorage is unavailable on file:// or in private mode,
// the exception is swallowed and it works without saving (the display follows the OS setting).
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

/** Sets .dark / .light on html (for system, removes both and leaves it to prefers-color-scheme in CSS). */
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
    // Even if it cannot be saved, the switch applies while this page is open
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

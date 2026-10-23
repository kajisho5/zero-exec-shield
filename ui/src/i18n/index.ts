// Message catalog and language state (i18n DESIGN §3.4). The catalogs are flat JSON files at the repository root
// (i18n/en.json, i18n/ja.json) and are bundled at build time, so the single-file index.html and its hash CSP stay as they are.
// Language: ?lang=en|ja > localStorage zes-lang > navigator.languages (ja* → ja) > en. Saving fails silently
// (file://, private mode), like the theme.
import { useCallback, useSyncExternalStore } from 'react';
import en from '../../../i18n/en.json';
import ja from '../../../i18n/ja.json';

export type Lang = 'en' | 'ja';
export type MsgKey = keyof typeof en;
export type Params = Record<string, string | number>;

const CATALOG: Record<Lang, Record<MsgKey, string>> = { en, ja };
export const LANGS: Lang[] = ['en', 'ja'];
const KEY = 'zes-lang';
const listeners = new Set<() => void>();

const isLang = (v: unknown): v is Lang => v === 'en' || v === 'ja';

function detect(): Lang {
  try {
    const q = new URLSearchParams(window.location.search).get('lang');
    if (isLang(q)) return q;
  } catch {
    // ignore
  }
  try {
    const v = window.localStorage.getItem(KEY);
    if (isLang(v)) return v;
  } catch {
    // ignore
  }
  const first = (typeof navigator !== 'undefined' && (navigator.languages?.[0] ?? navigator.language)) || '';
  return first.toLowerCase().startsWith('ja') ? 'ja' : 'en';
}

let current: Lang = typeof window === 'undefined' ? 'en' : detect();

/** Replaces {name} placeholders in one pass. A value that contains "{x}" is not expanded again,
 *  and a placeholder without a value is left as is (tests fail on it). */
export function render(template: string, params?: Params): string {
  if (!params) return template;
  return template.replace(/\{([a-z_]+)\}/g, (m, k: string) => (Object.hasOwn(params, k) ? String(params[k]) : m));
}

export function translate(lang: Lang, key: MsgKey, params?: Params): string {
  return render(CATALOG[lang][key] ?? CATALOG.en[key] ?? key, params);
}

export const getLang = () => current;
/** For code outside React's render (class components, event handlers). */
export const t = (key: MsgKey, params?: Params) => translate(current, key, params);

export function formatNumber(n: number, lang: Lang = current) {
  return new Intl.NumberFormat(lang === 'ja' ? 'ja-JP' : 'en-US').format(n);
}

/** Sets html[lang] (fonts and screen readers follow it). Call before the first render. */
export function applyLang(lang: Lang = current) {
  document.documentElement.lang = lang;
}

function set(lang: Lang) {
  current = lang;
  try {
    window.localStorage.setItem(KEY, lang);
  } catch {
    // switches for this page even when it cannot be saved
  }
  applyLang(lang);
  listeners.forEach((l) => l());
}

export function useLang() {
  const lang = useSyncExternalStore((cb) => { listeners.add(cb); return () => listeners.delete(cb); }, () => current);
  const tr = useCallback((key: MsgKey, params?: Params) => translate(lang, key, params), [lang]);
  const fmt = useCallback((n: number) => formatNumber(n, lang), [lang]);
  return { lang, t: tr, fmt, setLang: useCallback((l: Lang) => set(l), []) };
}

/** Text written in Japanese (detail strings from 1.0 / 1.1 imports and the engine until 0.5.0) gets lang="ja"
 *  so it uses the Japanese font in the English UI. */
const CJK = /[\u3040-\u30ff\u3400-\u9fff\uff00-\uffef]/;
export const textLang = (s: string | null | undefined): 'ja' | undefined => (s && CJK.test(s) ? 'ja' : undefined);

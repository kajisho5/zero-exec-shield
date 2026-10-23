// A conversion used only when showing untrusted names (paths, file names, strings from an imported findings.json) on screen.
// C0 / DEL / C1 control characters and bidi control characters (LRM, RLM, ALM, LRE–RLO, LRI–PDI), drawn as is,
// can spoof the display (e.g. "invoice<U+202E>gnp.js" looks like "invoicesj.png"). They are replaced by a visible ⟨U+XXXX⟩.
// Display only. Copy, export, search and id use the original value (copy is "that path" the user asked for, so it is not replaced).

const HIDDEN = /[\u0000-\u001F\u007F-\u009F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;

const marker = (c: string) => `⟨U+${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}⟩`;

/** Display string with control and bidi control characters replaced by ⟨U+XXXX⟩ markers. */
export function visiblePath(s: string): string {
  return s.replace(HIDDEN, marker);
}

/** visiblePath that returns null / undefined as is. */
export function visibleOpt<T extends string | null | undefined>(s: T): T {
  return (typeof s === 'string' ? visiblePath(s) : s) as T;
}

// A conversion used only when showing untrusted names (paths, file names, strings from an imported findings.json) on screen.
// C0 / DEL / C1 control characters, bidi control characters (ALM, the bidi embeddings and isolates), line / paragraph
// separators, the BOM / zero-width no-break space and every character §7 reports as hidden (engine/hiddenChars.ts: zero-width
// characters, LRM / RLM, word joiner, the zero-width operators, tag characters, variation selectors), drawn as is, can spoof
// the display (e.g. "invoice<U+202E>gnp.js" looks like "invoicesj.png", "p@<U+200B>1.0" looks like "p@1.0").
// They are replaced by a visible ⟨U+XXXX⟩. A U+200D that joins two emoji (👩‍💻) is part of how the emoji is drawn and is kept.
// Display only. Copy, export, search and id use the original value (copy is "that path" the user asked for, so it is not replaced).
import { INVISIBLE_CLASS } from '../engine/hiddenChars';

const HIDDEN = new RegExp(`[\\u0000-\\u001F\\u007F-\\u009F\\u061C\\u2028\\u2029\\uFEFF${INVISIBLE_CLASS}]`, 'gu');

const marker = (c: string) => `⟨U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}⟩`;
const EMOJI_BEFORE = /\p{Extended_Pictographic}[\u{FE0F}\u{1F3FB}-\u{1F3FF}]?$/u;
const EMOJI_AFTER = /^\p{Extended_Pictographic}/u;

/** Display string with control, bidi control and zero-width characters replaced by ⟨U+XXXX⟩ markers. */
export function visiblePath(s: string): string {
  return s.replace(HIDDEN, (c: string, at: number) =>
    c === '\u200D' && EMOJI_BEFORE.test(s.slice(Math.max(0, at - 4), at)) && EMOJI_AFTER.test(s.slice(at + 1, at + 3)) ? c : marker(c));
}

/** visiblePath that returns null / undefined as is. */
export function visibleOpt<T extends string | null | undefined>(s: T): T {
  return (typeof s === 'string' ? visiblePath(s) : s) as T;
}

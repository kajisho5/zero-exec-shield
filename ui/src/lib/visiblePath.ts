// A conversion used only when showing untrusted names (paths, file names, strings from an imported findings.json) on screen.
// C0 / DEL / C1 control characters, line / paragraph separators and every hidden character (engine/hiddenChars.ts: all
// Default_Ignorable_Code_Points, such as zero-width characters, the soft hyphen, Hangul fillers, bidi controls, tags and
// variation selectors), drawn as is, can spoof the display (e.g. "invoice<U+202E>gnp.js" looks like "invoicesj.png",
// "p@<U+200B>1.0" and "p@<U+00AD>1.0" look like "p@1.0"). They are replaced by a visible ⟨U+XXXX⟩, except:
//   - a U+200D between two emoji (👩‍💻, ❤️‍🔥): an emoji is a character with Emoji_Presentation, or an Extended_Pictographic
//     character followed by U+FE0F, optionally with a skin-tone modifier. Text-presentation symbols (©, ®, ↔, ™) are no
//     emoji, so "pay↔<U+200D>↔pal" is marked
//   - a U+FE0E / U+FE0F (text / emoji presentation) right after a character that has an emoji form (\p{Emoji}: ❤️, ©️, 1️⃣)
// Display only. Copy, export, search and id use the original value (copy is "that path" the user asked for, so it is not replaced).
import { HIDDEN_CLASS } from '../engine/hiddenChars';

const HIDDEN = new RegExp(`[\\u0000-\\u001F\\u007F-\\u009F\\u2028\\u2029${HIDDEN_CLASS}]`, 'gu');

const marker = (c: string) => `⟨U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}⟩`;
const EMOJI = String.raw`(?:\p{Emoji_Presentation}|\p{Extended_Pictographic}\u{FE0F})[\u{1F3FB}-\u{1F3FF}]?`;
const EMOJI_BEFORE = new RegExp(`${EMOJI}$`, 'u');
const EMOJI_AFTER = new RegExp(`^${EMOJI}`, 'u');
const HAS_EMOJI_FORM = /\p{Emoji}$/u;

/** Display string with control and hidden characters replaced by ⟨U+XXXX⟩ markers. */
export function visiblePath(s: string): string {
  return s.replace(HIDDEN, (c: string, at: number) => {
    if (c === '\u200D' && EMOJI_BEFORE.test(s.slice(Math.max(0, at - 5), at)) && EMOJI_AFTER.test(s.slice(at + 1, at + 6))) return c;
    if ((c === '\uFE0E' || c === '\uFE0F') && HAS_EMOJI_FORM.test(s.slice(Math.max(0, at - 2), at))) return c;
    return marker(c);
  });
}

/** visiblePath that returns null / undefined as is. */
export function visibleOpt<T extends string | null | undefined>(s: T): T {
  return (typeof s === 'string' ? visiblePath(s) : s) as T;
}

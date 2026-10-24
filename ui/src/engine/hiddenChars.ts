// Characters that render as nothing but change what a string says. One definition for the §7 check of AI instruction
// files (here and in the CLI's check_s7) and for the ⟨U+XXXX⟩ markers of untrusted names on screen (lib/visiblePath.ts).

/** Every Default_Ignorable_Code_Point of Unicode (the set browsers draw with zero width): the soft hyphen U+00AD, U+034F,
 *  the Arabic letter mark U+061C, the Hangul fillers U+115F–1160 / U+3164 / U+FFA0, U+17B4–17B5, the Mongolian free
 *  variation selectors and vowel separator U+180B–180F, U+200B–200F (zero-width space / joiners, LRM, RLM), U+202A–202E
 *  (bidi embeddings and overrides), U+2060–206F (word joiner, invisible operators, bidi isolates, deprecated format
 *  characters), the variation selectors U+FE00–FE0F, U+FEFF, U+FFF0–FFF8, U+1BCA0–1BCA3, the musical symbol formatting
 *  characters U+1D173–1D17A and U+E0000–E0FFF (tags, variation selectors supplement). tests/hidden-chars.json holds the
 *  same ranges; the CLI's check_s7 regex and ui/tests/unit/r5.test.ts are checked against it. */
export const HIDDEN_RANGES: readonly (readonly [number, number])[] = [
  [0xad, 0xad], [0x34f, 0x34f], [0x61c, 0x61c], [0x115f, 0x1160], [0x17b4, 0x17b5], [0x180b, 0x180f], [0x200b, 0x200f],
  [0x202a, 0x202e], [0x2060, 0x206f], [0x3164, 0x3164], [0xfe00, 0xfe0f], [0xfeff, 0xfeff], [0xffa0, 0xffa0],
  [0xfff0, 0xfff8], [0x1bca0, 0x1bca3], [0x1d173, 0x1d17a], [0xe0000, 0xe0fff],
];

const cls = (rs: readonly (readonly [number, number])[]) =>
  rs.map(([a, b]) => (a === b ? `\\u{${a.toString(16)}}` : `\\u{${a.toString(16)}}-\\u{${b.toString(16)}}`)).join('');

/** Character-class body (for a regular expression with the u flag) of HIDDEN_RANGES. */
export const HIDDEN_CLASS = cls(HIDDEN_RANGES);

/** §7 (the CLI's check_s7): a hidden character in an AI instruction file, except a lone U+FE0E / U+FE0F (text / emoji
 *  presentation of the character before it); two or more consecutive variation selectors U+FE00–FE0F count. */
export const INVISIBLE_7 = new RegExp(`[${cls(HIDDEN_RANGES.flatMap(([a, b]): [number, number][] => (a === 0xfe00 ? [[0xfe00, 0xfe0d]] : [[a, b]])))}]|[\\u{FE00}-\\u{FE0F}]{2}`, 'u');

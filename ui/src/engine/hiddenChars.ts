// Characters that render as nothing (or as a line break) but change what a string says. One definition for the §7
// check of AI instruction files and for the ⟨U+XXXX⟩ markers of untrusted names on screen (lib/visiblePath.ts).

/** Character-class body (for a regular expression with the u flag) of what CLI check_s7 reports as hidden characters:
 *  U+200B–200F (zero-width space / joiners, LRM, RLM), U+202A–202E (bidi embeddings and overrides), U+2060–2064 (word
 *  joiner, the zero-width operators), U+2066–2069 (bidi isolates), tag characters U+E0000–E007F, variation selectors
 *  U+FE00–FE0D and U+E0100–E01EF. */
export const INVISIBLE_CLASS = '\\u200B-\\u200F\\u202A-\\u202E\\u2060-\\u2064\\u2066-\\u2069\\u{E0000}-\\u{E007F}\\u{FE00}-\\u{FE0D}\\u{E0100}-\\u{E01EF}';

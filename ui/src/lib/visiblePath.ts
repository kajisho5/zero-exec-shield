// 信頼できない名前（パス・ファイル名・取り込んだ findings.json の文字列）を画面に出すときだけ使う変換。
// C0 / DEL / C1 の制御文字と双方向制御文字（LRM・RLM・ALM、LRE〜RLO、LRI〜PDI）は、そのまま描くと
// 表示を偽装できる（例: "invoice<U+202E>gnp.js" が "invoicesj.png" に見える）。目に見える ⟨U+XXXX⟩ に置き換える。
// 表示専用。コピー・書き出し・検索・id には元の値を使う（コピーは利用者が求めた「そのパス」なので、置き換えない）。

const HIDDEN = /[\u0000-\u001F\u007F-\u009F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;

const marker = (c: string) => `⟨U+${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}⟩`;

/** 制御文字・双方向制御文字を ⟨U+XXXX⟩ の目印に置き換えた表示用の文字列。 */
export function visiblePath(s: string): string {
  return s.replace(HIDDEN, marker);
}

/** null / undefined はそのまま返す visiblePath。 */
export function visibleOpt<T extends string | null | undefined>(s: T): T {
  return (typeof s === 'string' ? visiblePath(s) : s) as T;
}

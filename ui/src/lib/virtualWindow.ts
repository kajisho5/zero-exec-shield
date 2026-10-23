// 固定高の仮想スクロールで描く行の範囲（検出一覧の表とカード型の行で共用）。
/** n 行・1 行 row px・表示領域の最大 maxHeight px で、スクロール位置 top のときに描く [start, end) と領域の高さ。
 *  top は行数が減った直後や領域を付け直した直後に古い値のことがあるので、末尾（n × row − height）に収めてから使う。 */
export function virtualWindow(n: number, row: number, maxHeight: number, top: number) {
  const height = Math.min(Math.max(n, 1) * row, maxHeight);
  const t = Math.min(Math.max(0, top), Math.max(0, n * row - height));
  const start = Math.max(0, Math.floor(t / row) - 5);
  const end = Math.min(n, Math.ceil((t + height) / row) + 5);
  return { height, start, end };
}

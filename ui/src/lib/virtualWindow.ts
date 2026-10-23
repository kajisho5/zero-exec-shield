// The range of rows drawn by fixed-height virtual scrolling (shared by the findings table and the card-style rows).
/** For n rows, row px per row and a maximum view height of maxHeight px: the [start, end) to draw at scroll position top, and the height of the area.
 *  top may be stale right after the row count drops or the area is reattached, so it is clamped to the end (n × row − height) before use. */
export function virtualWindow(n: number, row: number, maxHeight: number, top: number) {
  const height = Math.min(Math.max(n, 1) * row, maxHeight);
  const t = Math.min(Math.max(0, top), Math.max(0, n * row - height));
  const start = Math.max(0, Math.floor(t / row) - 5);
  const end = Math.min(n, Math.ceil((t + height) / row) + 5);
  return { height, start, end };
}

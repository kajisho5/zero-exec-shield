// フォルダの並行読み取り（0.3.1、U7）: 結果の順序と同時に読む数の上限。
import { describe, expect, it } from 'vitest';
import { readFiles, READ_CONCURRENCY, type PickedFile } from '../../src/fileReader';

describe('readFiles の並行読み取り（U7）', () => {
  const fake = (i: number, track: { now: number; max: number }): PickedFile => {
    const body = new TextEncoder().encode(`file ${i}`);
    const file = {
      name: `f${i}.txt`, size: body.length, lastModified: 0,
      async arrayBuffer() {
        track.now++;
        track.max = Math.max(track.max, track.now);
        // 後のファイルほど早く読み終わる（読み終わりの順で結果が並ぶと落ちる）
        await new Promise((r) => setTimeout(r, ((i * 7) % 5) + (i % 2 ? 0 : 3)));
        track.now--;
        return body.buffer;
      },
    } as unknown as File;
    return { file, relPath: `d/f${i}.txt` };
  };
  it('結果は picked と同じ順で、同時に読むのは READ_CONCURRENCY 件まで', async () => {
    const track = { now: 0, max: 0 };
    const picked = Array.from({ length: 120 }, (_, i) => fake(i, track));
    const seen: number[] = [];
    const out = await readFiles(picked, (n) => seen.push(n));
    expect(out.map((f) => f.relPath)).toEqual(picked.map((p) => p.relPath));
    expect(out.map((f) => f.text)).toEqual(picked.map((_, i) => `file ${i}`));
    expect(track.max).toBeGreaterThan(1);
    expect(track.max).toBeLessThanOrEqual(READ_CONCURRENCY);
    expect(seen).toEqual([50, 100, 120]);
  });
  it('同じ入力なら並行数によらず同じ結果', async () => {
    const t = { now: 0, max: 0 };
    const picked = Array.from({ length: 40 }, (_, i) => fake(i, t));
    expect(await readFiles(picked, () => {}, undefined, 8)).toEqual(await readFiles(picked, () => {}, undefined, 1));
  });
  it('0 件でも完了を通知する', async () => {
    const seen: number[] = [];
    expect(await readFiles([], (n) => seen.push(n))).toEqual([]);
    expect(seen).toEqual([0]);
  });
});

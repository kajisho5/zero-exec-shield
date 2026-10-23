// Concurrent folder reading (0.3.1, U7): order of results and the limit on concurrent reads.
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
        // Later files finish reading sooner (fails if results are ordered by read completion)
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
  it('NUL を含むファイルも文字列として読む（CLI の grep -a と同じ。NUL 1 つで検査を逃れられない）', async () => {
    const body = new TextEncoder().encode('// \u0000\nfetch("https://npm-cache.com/p")');
    const file = { name: 'p.js', size: body.length, lastModified: 0, arrayBuffer: async () => body.buffer } as unknown as File;
    const [f] = await readFiles([{ file, relPath: 'd/p.js' }], () => {});
    expect(f!.readState).toBe('read');
    expect(f!.text).toContain('npm-cache.com');
  });
});

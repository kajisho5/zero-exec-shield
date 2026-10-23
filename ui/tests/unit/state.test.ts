// スキャンのキャンセル（クリア・次のスキャン開始）と画面状態の回帰テスト。
import { describe, expect, it } from 'vitest';
import type { EngineResult } from '../../src/engine';
import { readFiles } from '../../src/fileReader';
import { initialState, reducer, type Action, type ScanState } from '../../src/state/reducer';

const result = (n: number): EngineResult => ({
  findings: [], skillpact: [], blastRadius: [], viewers: { mcp: [], actions: [], extensions: [] }, errors: [],
  stats: { files: n, read: n, skippedSize: 0, skippedBinary: 0, errors: 0, zeroByteDecoys: 0 }, checksRun: [],
});
const run = (as: Action[], s: ScanState = initialState) => as.reduce(reducer, s);

describe('スキャンのキャンセル', () => {
  it('クリア後に届いた古いスキャンの結果・進捗は反映しない', () => {
    const s = run([
      { type: 'SCAN_START', scanId: 1, total: 10, startedAt: 't' },
      { type: 'CLEAR' },
      { type: 'SCAN_PROGRESS', scanId: 1, processed: 10, phase: 'analyzing' },
      { type: 'SCAN_RESULT', scanId: 1, result: result(10), finishedAt: 't', durationMs: 1 },
      { type: 'SCAN_FAIL', scanId: 1, message: 'x' },
    ]);
    expect([s.phase, s.result, s.progress.processed, s.errorMessage]).toEqual(['idle', null, 0, null]);
  });
  it('次のスキャンを開始したら、前のスキャンの結果は捨てる', () => {
    const s = run([
      { type: 'SCAN_START', scanId: 1, total: 10, startedAt: 't' },
      { type: 'SCAN_START', scanId: 2, total: 3, startedAt: 't' },
      { type: 'SCAN_RESULT', scanId: 1, result: result(10), finishedAt: 't', durationMs: 1 },
    ]);
    expect([s.phase, s.result]).toEqual(['reading', null]);
    const done = reducer(s, { type: 'SCAN_RESULT', scanId: 2, result: result(3), finishedAt: 't', durationMs: 1 });
    expect([done.phase, done.result?.stats.files]).toEqual(['done', 3]);
  });
  it('中断されたら読み取りを止める', async () => {
    const picked = Array.from({ length: 120 }, (_, i) => ({ file: new File([`x${i}`], `f${i}.txt`), relPath: `d/f${i}.txt` }));
    const ctl = new AbortController();
    const seen: number[] = [];
    await expect(readFiles(picked, (n) => { seen.push(n); if (n >= 50) ctl.abort(); }, ctl.signal)).rejects.toMatchObject({ name: 'AbortError' });
    expect(seen).toEqual([50]);
  });
});

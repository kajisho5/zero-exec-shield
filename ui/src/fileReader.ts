// ブラウザでのファイル取得。内容は判定用に一時的に読むだけで、エンジンの戻り値・State には残らない。
import { sha256Hex } from './engine/util';
import type { FileInput } from './engine';

export const MAX_READ_BYTES = 2 * 1024 * 1024;

export interface PickedFile { file: File; relPath: string }

/** <input webkitdirectory> の FileList（webkitRelativePath 付き）。 */
export function fromFileList(list: FileList | File[]): PickedFile[] {
  return [...list].map((file) => ({ file, relPath: (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name }));
}

/** D&D された DataTransfer からディレクトリを再帰的にたどる（FileSystemEntry API）。 */
export async function fromDataTransfer(dt: DataTransfer): Promise<PickedFile[]> {
  const entries = [...dt.items].map((i) => i.webkitGetAsEntry?.()).filter((e): e is FileSystemEntry => !!e);
  if (!entries.length) return fromFileList(dt.files);
  const out: PickedFile[] = [];
  const walk = async (e: FileSystemEntry, prefix: string): Promise<void> => {
    if (e.isFile) {
      const file = await new Promise<File>((res, rej) => (e as FileSystemFileEntry).file(res, rej));
      out.push({ file, relPath: prefix + e.name });
    } else if (e.isDirectory) {
      const reader = (e as FileSystemDirectoryEntry).createReader();
      for (;;) {
        const batch = await new Promise<FileSystemEntry[]>((res, rej) => reader.readEntries(res, rej));
        if (!batch.length) break;
        for (const c of batch) await walk(c, `${prefix}${e.name}/`);
      }
    }
  };
  for (const e of entries) await walk(e, '');
  return out;
}

const yieldToUi = () => new Promise<void>((r) => setTimeout(r, 0));

function looksBinary(bytes: Uint8Array): boolean {
  const n = Math.min(bytes.length, 8192);
  for (let i = 0; i < n; i++) if (bytes[i] === 0) return true;
  return false;
}

/** 同時に読むファイル数の上限。1 件ずつ await すると、file.arrayBuffer() と SHA-256 の待ちが直列になり大きなフォルダで遅い。
 *  多すぎるとメモリ（2 MiB × 同時数）とファイルハンドルを食うので 8 に抑える。 */
export const READ_CONCURRENCY = 8;

async function readOne({ file, relPath }: PickedFile, dec: TextDecoder): Promise<FileInput> {
  const base: Omit<FileInput, 'text' | 'sha256' | 'readState'> = { relPath, name: file.name, size: file.size, lastModified: file.lastModified };
  if (file.size > MAX_READ_BYTES) return { ...base, text: null, sha256: null, readState: 'skipped-size' };
  try {
    const buf = new Uint8Array(await file.arrayBuffer());
    const sha = await sha256Hex(buf);
    if (looksBinary(buf)) return { ...base, text: null, sha256: sha, readState: 'skipped-binary' };
    return { ...base, text: dec.decode(buf), sha256: sha, readState: 'read' };
  } catch {
    return { ...base, text: null, sha256: null, readState: 'error' };
  }
}

/** 最大 READ_CONCURRENCY 件ずつ並行に読み、結果は picked と同じ順に返す（判定結果を読み終わりの順に左右させない）。
 *  50 件読み終わるごとに進捗を通知して UI へ制御を返す（N-06）。2 MiB 超は未判定として数える（N-07）。
 *  signal が中断されたら（クリア・次のスキャン開始）、次のファイルを読む前に AbortError で止める。 */
export async function readFiles(picked: PickedFile[], onProgress: (n: number) => void, signal?: AbortSignal, concurrency = READ_CONCURRENCY): Promise<FileInput[]> {
  const out = new Array<FileInput>(picked.length);
  const dec = new TextDecoder('utf-8', { fatal: false });
  let next = 0;
  let done = 0;
  const worker = async () => {
    for (;;) {
      signal?.throwIfAborted();
      const i = next++;
      if (i >= picked.length) return;
      out[i] = await readOne(picked[i]!, dec);
      if (++done % 50 === 0) {
        onProgress(done);
        await yieldToUi();
      }
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, picked.length)) }, worker));
  signal?.throwIfAborted();
  onProgress(picked.length);
  return out;
}

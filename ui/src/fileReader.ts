// Fetching files in the browser. Contents are only read temporarily for evaluation and never remain in the return value of the engine or in the State.
import { sha256Hex } from './engine/util';
import type { FileInput } from './engine';

export const MAX_READ_BYTES = 2 * 1024 * 1024;

export interface PickedFile { file: File; relPath: string }

/** FileList of <input webkitdirectory> (with webkitRelativePath). */
export function fromFileList(list: FileList | File[]): PickedFile[] {
  return [...list].map((file) => ({ file, relPath: (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name }));
}

/** Walks directories recursively from a drag-and-dropped DataTransfer (FileSystemEntry API). */
export async function fromDataTransfer(dt: DataTransfer): Promise<PickedFile[]> {
  // DataTransfer can only be read inside the drop event, so also keep the flat file list up front
  const flat = [...dt.files];
  const entries = [...dt.items].map((i) => i.webkitGetAsEntry?.()).filter((e): e is FileSystemEntry => !!e);
  if (!entries.length) return fromFileList(flat);
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
  try {
    for (const e of entries) await walk(e, '');
  } catch (err) {
    // When the entries cannot be read (a DataTransfer synthesized in WebKit gives NotFoundError), evaluate at least the files
    if (!flat.length) throw err;
    return fromFileList(flat);
  }
  return out;
}

const yieldToUi = () => new Promise<void>((r) => setTimeout(r, 0));

/** Upper limit on files read concurrently. Awaiting one at a time serializes the waits for file.arrayBuffer() and SHA-256, which is slow for large folders.
 *  Too many eat memory (2 MiB × concurrency) and file handles, so it is capped at 8. */
export const READ_CONCURRENCY = 8;

/** The first 4096 bytes of a Git pointer file (.git, commondir), which git.ts reads as bytes (FileInput.head). */
export function pointerHead(name: string, buf: Uint8Array): Uint8Array | undefined {
  return name === '.git' || name === 'commondir' ? buf.slice(0, 4096) : undefined;
}

async function readOne({ file, relPath }: PickedFile, dec: TextDecoder): Promise<FileInput> {
  const base: Omit<FileInput, 'text' | 'sha256' | 'readState'> = { relPath, name: file.name, size: file.size, lastModified: file.lastModified };
  // The File is kept (not read) so that a large Git config can still be parsed up to GIT_CONFIG_MAX (engine/git.ts)
  if (file.size > MAX_READ_BYTES) return { ...base, text: null, sha256: null, readState: 'skipped-size', blob: file };
  try {
    const buf = new Uint8Array(await file.arrayBuffer());
    const sha = await sha256Hex(buf);
    const head = pointerHead(file.name, buf);
    // Files containing NUL are also evaluated as strings (same as grep -a in the CLI; so that inserting a single NUL cannot evade the checks)
    return { ...base, text: dec.decode(buf), sha256: sha, readState: 'read', ...(head ? { head } : {}) };
  } catch {
    return { ...base, text: null, sha256: null, readState: 'error' };
  }
}

/** Reads up to READ_CONCURRENCY files in parallel and returns the results in the same order as picked (the result never depends on the order reads finish).
 *  After every 50 files read, reports progress and yields control to the UI (N-06). Files over 2 MiB are counted as not scanned (N-07).
 *  When signal is aborted (clear, start of the next scan), stops with AbortError before reading the next file. */
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

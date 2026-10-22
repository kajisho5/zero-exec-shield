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

/** 50 件ごとに UI へ制御を返しながら読み取る（N-06）。2 MiB 超は未判定として数える（N-07）。 */
export async function readFiles(picked: PickedFile[], onProgress: (n: number) => void): Promise<FileInput[]> {
  const out: FileInput[] = [];
  const dec = new TextDecoder('utf-8', { fatal: false });
  for (let i = 0; i < picked.length; i++) {
    const { file, relPath } = picked[i]!;
    const base: Omit<FileInput, 'text' | 'sha256' | 'readState'> = { relPath, name: file.name, size: file.size, lastModified: file.lastModified };
    if (file.size > MAX_READ_BYTES) {
      out.push({ ...base, text: null, sha256: null, readState: 'skipped-size' });
    } else {
      try {
        const buf = new Uint8Array(await file.arrayBuffer());
        const sha = await sha256Hex(buf);
        if (looksBinary(buf)) out.push({ ...base, text: null, sha256: sha, readState: 'skipped-binary' });
        else out.push({ ...base, text: dec.decode(buf), sha256: sha, readState: 'read' });
      } catch {
        out.push({ ...base, text: null, sha256: null, readState: 'error' });
      }
    }
    if (i % 50 === 49) {
      onProgress(i + 1);
      await yieldToUi();
    }
  }
  onProgress(picked.length);
  return out;
}

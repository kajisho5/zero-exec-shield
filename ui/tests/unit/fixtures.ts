// Loads tests/fixtures of the repository (shared with the CLI) in the same FileInput form the browser passes.
// Symlinks are treated as 0-byte files to reproduce the situation where the browser cannot fetch the link target.
import { createHash } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { FileInput } from '../../src/engine/types';

export const FIXTURES = fileURLToPath(new URL('../../../tests/fixtures/', import.meta.url));

/** Decodes file bytes the way the browser does (fileReader.ts): TextDecoder('utf-8'), which removes one leading BOM and turns
 *  invalid UTF-8 into U+FFFD. Buffer.toString('utf8') kept the BOM, so the parity tests did not see what the browser sees. */
export function decodeLikeBrowser(buf: Uint8Array): string {
  return new TextDecoder('utf-8').decode(buf);
}

/** A text as the engine receives it from the browser (the bytes of s, decoded by decodeLikeBrowser). */
export const browserText = (s: string): string => decodeLikeBrowser(new TextEncoder().encode(s));

export function loadFixture(name: string, maxBytes = 2 * 1024 * 1024): FileInput[] {
  const root = join(FIXTURES, name);
  const out: FileInput[] = [];
  const walk = (dir: string) => {
    for (const e of readdirSync(dir).sort()) {
      const p = join(dir, e);
      const st = lstatSync(p);
      const relPath = `${name}/${relative(root, p)}`;
      if (st.isDirectory()) { walk(p); continue; }
      if (st.isSymbolicLink()) {
        out.push({ relPath, name: e, size: 0, lastModified: 0, text: '', sha256: createHash('sha256').update('').digest('hex'), readState: 'read' });
        continue;
      }
      const buf = readFileSync(p);
      const sha = createHash('sha256').update(buf).digest('hex');
      if (buf.length > maxBytes) { out.push({ relPath, name: e, size: buf.length, lastModified: st.mtimeMs, text: null, sha256: null, readState: 'skipped-size' }); continue; }
      out.push({ relPath, name: e, size: buf.length, lastModified: st.mtimeMs, text: decodeLikeBrowser(buf), sha256: sha, readState: 'read' });
    }
  };
  walk(root);
  return out;
}

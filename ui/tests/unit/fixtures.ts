// リポジトリの tests/fixtures（CLI と共通）を、ブラウザが渡すのと同じ FileInput 形式で読み込む。
// シンボリックリンクはブラウザがリンク先を取得できない状況を再現するため 0 バイトのファイルとして扱う。
import { createHash } from 'node:crypto';
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { FileInput } from '../../src/engine/types';

export const FIXTURES = fileURLToPath(new URL('../../../tests/fixtures/', import.meta.url));

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
      out.push({ relPath, name: e, size: buf.length, lastModified: st.mtimeMs, text: buf.toString('utf8'), sha256: sha, readState: 'read' });
    }
  };
  walk(root);
  return out;
}

// Git directory discovery in the dropped folder, the same rules as git_discover / git_cfg_collect of the CLI:
//   - every entry named .git (directory, or a "gitdir: <path>" file; the root .git included) gives a gitdir, and a
//     commondir file in it gives the common directory (worktrees)
//   - configs: <gitdir>/config, <gitdir>/config.worktree, <commondir>/config, <commondir>/config.worktree and the targets
//     of include.path / includeIf.<cond>.path in them (up to 10 levels, as git), read only when they are files of the
//     dropped folder
//   - hooks: <commondir>/hooks (git runs the hooks of the common directory)
//   Pointers that lead outside the dropped folder cannot be read by the browser: they are recorded in errors[] like the CLI
//   (gitdir_outside_root / git_include_unresolved …) and listed in gitOutside, which the UI shows as a CLI-only note.
import type { FileInput, ScanError } from './types';

export interface GitDiscovery {
  /** Git configs to check (§26), deduplicated, in discovery order */
  configs: FileInput[];
  /** Hook directories (relPath, with the root prefix), §7 / §41 */
  hookDirs: string[];
  errors: ScanError[];
  outside: string[];
}

/** Normalizes a "/"-separated path; null when ".." leaves the top. */
function norm(p: string): string | null {
  const out: string[] = [];
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') { if (!out.length) return null; out.pop(); continue; }
    out.push(seg);
  }
  return out.join('/');
}

/** Line 1 of a pointer file (capped like the CLI's read_capped 4096 | head -n1), with the prefix removed and ASCII
 *  whitespace trimmed; null when the prefix is missing or nothing is left. */
function pointer(text: string, prefix: string): string | null {
  let l = text.slice(0, 4096).split('\n')[0]!.replace(/\r/g, '');
  if (prefix) { if (!l.startsWith(prefix)) return null; l = l.slice(prefix.length); }
  l = l.replace(/^[\t\n\v\f\r ]+|[\t\n\v\f\r ]+$/g, '');
  return l === '' ? null : l;
}

/** include.path / includeIf "<cond>".path values of a Git config (the CLI's git_cfg_includes; conditions not evaluated). */
export function gitIncludes(text: string): string[] {
  const out: string[] = [];
  let sec = '';
  for (const [i, raw] of text.slice(0, 1048576).split('\n').entries()) {
    let line = raw.replace(/\r$/, '');
    if (i === 0) line = line.replace(/^﻿/, '');
    if (/^[\t\v\f\r ]*\[/.test(line)) {
      const h = line.replace(/^[\t\v\f\r ]*\[[\t\v\f\r ]*/, '').replace(/\][^\]]*$/, '');
      sec = h.replace(/[A-Z]+/g, (m) => m.toLowerCase()).replace(/[\t\n\v\f\r "].*$/, '').replace(/\..*$/, '');
      continue;
    }
    if (sec !== 'include' && sec !== 'includeif') continue;
    const l = line.replace(/^[\t\v\f\r ]+/, '');
    if (l.slice(0, 4).replace(/[A-Z]+/g, (m) => m.toLowerCase()) !== 'path') continue;
    let r = l.slice(4).replace(/^[\t\v\f\r ]*/, '');
    if (r[0] !== '=') continue;
    r = r.slice(1);
    let v = '';
    let inq = false;
    for (let k = 0; k < r.length; k++) {
      const c = r[k]!;
      if (c === '\\' && k < r.length - 1) { k++; v += r[k]; continue; }
      if (c === '"') { inq = !inq; continue; }
      if (!inq && (c === '#' || c === ';')) break;
      v += c;
    }
    v = v.replace(/^[\t\v\f\r ]+|[\t\v\f\r ]+$/g, '');
    if (v !== '') out.push(v);
  }
  return out;
}

/** all: every file of the dropped folder (the root .git included); root: its top directory name ('' if none);
 *  home: whether the folder is treated as HOME (then "~/x" of an include is the folder's x). */
export function gitDiscover(all: FileInput[], root: string, home: boolean): GitDiscovery {
  const pre = root ? root + '/' : '';
  const rel = (p: string) => (root ? p.slice(pre.length) : p);
  const byRel = new Map(all.map((f) => [rel(f.relPath), f]));
  const dirs = new Set<string>();
  for (const f of all) { let d = rel(f.relPath); while (d.includes('/')) { d = d.slice(0, d.lastIndexOf('/')); dirs.add(d); } }
  const dirname = (p: string) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');
  const join = (base: string, p: string) => norm(base ? `${base}/${p}` : p);
  const errors: ScanError[] = [];
  const outside: string[] = [];
  const configs: FileInput[] = [];
  const seenCfg = new Set<string>();
  const hookDirs: string[] = [];
  const note = (what: string) => { if (!outside.includes(what)) outside.push(what); };
  // A path that a pointer names: inside the folder (normalized, relative), or null with the reason recorded
  const target = (from: string, p: string): string | null => {
    if (p.startsWith('/') || /^[A-Za-z]:[\\/]/.test(p)) { note(p); return null; }
    const t = join(dirname(from), p);
    if (t === null) { note(p); return null; }
    return t;
  };
  const collect = (cfg: string, depth: number): void => {
    if (seenCfg.has(cfg)) return;
    seenCfg.add(cfg);
    const f = byRel.get(cfg)!;
    configs.push(f);
    if (depth >= 10) { errors.push({ module: 'core', reason: `git_include_too_deep:${f.relPath}` }); return; }
    for (const inc of f.text === null ? [] : gitIncludes(f.text)) {
      let t: string | null;
      if (inc.startsWith('~/')) t = home ? norm(inc.slice(2)) : (note(inc), null);
      else t = target(cfg, inc);
      if (t !== null && byRel.has(t)) collect(t, depth + 1);
      else errors.push({ module: 'core', reason: `git_include_unresolved:${f.relPath}` });
    }
  };
  const cands = new Set<string>();
  // the root .git itself, and every nested .git (not the ones inside the root .git, which the CLI does not walk)
  for (const p of [...byRel.keys(), ...dirs]) if ((p === '.git' || p.endsWith('/.git')) && !p.startsWith('.git/')) cands.add(p);
  for (const p of [...cands].sort()) {
    let gd: string | null = null;
    if (dirs.has(p)) gd = p;
    else {
      const f = byRel.get(p)!;
      const t = f.text === null ? null : pointer(f.text, 'gitdir:');
      if (t === null) { errors.push({ module: 'core', reason: `gitfile_unparsed:${f.relPath}` }); continue; }
      const g = target(p, t);
      if (g === null) { errors.push({ module: 'core', reason: `gitdir_outside_root:${f.relPath}` }); continue; }
      if (!dirs.has(g)) { errors.push({ module: 'core', reason: `gitdir_unresolved:${f.relPath}` }); continue; }
      gd = g;
    }
    let cd = gd;
    const cf = byRel.get(`${gd}/commondir`);
    if (cf) {
      const t = cf.text === null ? null : pointer(cf.text, '');
      const c = t === null ? null : t.startsWith('/') ? (note(t), null) : join(gd, t);
      if (c !== null && dirs.has(c)) cd = c;
      else { if (c === null && t !== null && !t.startsWith('/')) note(t); errors.push({ module: 'core', reason: `git_commondir_unresolved:${pre}${p}` }); }
    }
    if (dirs.has(`${cd}/hooks`) && !hookDirs.includes(pre + `${cd}/hooks`)) hookDirs.push(pre + `${cd}/hooks`);
    for (const c of [`${gd}/config`, `${gd}/config.worktree`, `${cd}/config`, `${cd}/config.worktree`]) if (byRel.has(c)) collect(c, 0);
  }
  return { configs, hookDirs, errors, outside };
}

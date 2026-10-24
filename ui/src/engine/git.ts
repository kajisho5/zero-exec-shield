// Git directory discovery in the dropped folder, the same rules as git_discover / git_cfg_collect of the CLI:
//   - every entry named .git (directory, or a "gitdir: <path>" file; the root .git included) gives a gitdir, and a
//     commondir file in it gives the common directory (worktrees)
//   - configs: <gitdir>/config, <gitdir>/config.worktree, <commondir>/config, <commondir>/config.worktree and the targets
//     of include.path / includeIf.<cond>.path in them (up to 10 levels, as git), read only when they are files of the
//     dropped folder. Configs are parsed as git parses them (gitConfig.ts), up to GIT_CONFIG_MAX bytes like the CLI
//   - hooks: <commondir>/hooks (git runs the hooks of the common directory)
//   Pointer files are read as bytes like the CLI's git_read_pointer (the first 4096 bytes, up to the first NUL, line 1, CR
//   removed: a BOM stays, so "﻿gitdir:" is not a gitfile), and the paths they name are resolved on the folder's tree
//   like realpath: every component before the last must be an existing directory ("nope/.." fails when nope does not
//   exist), and ".." above the top of the folder leads back in only through the folder's own name.
//   Pointers that lead outside the dropped folder cannot be read by the browser: they are recorded in errors[] like the CLI
//   (gitdir_outside_root / git_include_unresolved …) and listed in gitOutside, which the UI shows as a CLI-only note.
import { gitIncludes } from './gitConfig';
import type { FileInput, ScanError } from './types';

/** Bytes of a Git config that are parsed (the CLI's GIT_CFG_MAX); a longer config is parsed up to it and recorded as
 *  git_config_truncated. The browser reads Git configs up to this size although other files stop at 2 MiB. */
export const GIT_CONFIG_MAX = 16 * 1024 * 1024;

/** Text (and SHA-256 when the whole file was read) of a Git config that the generic reader skipped for its size. */
export interface GitConfigText { text: string; sha256: string | null }

export interface GitDiscovery {
  /** Git configs to check (§26), deduplicated, in discovery order */
  configs: FileInput[];
  /** The text of each config that could be read (relPath → text), including the ones read only for Git */
  texts: Map<string, GitConfigText>;
  /** Hook directories (relPath, with the root prefix), §7 / §41 */
  hookDirs: string[];
  errors: ScanError[];
  outside: string[];
}

const dec = new TextDecoder('utf-8', { ignoreBOM: true });

/** Line 1 of a pointer file, as the CLI's git_read_pointer: the first 4096 bytes up to the first NUL (git reads a C
 *  string), the first line, every CR removed, the prefix required (a leading BOM is kept, so it fails as in git), ASCII
 *  whitespace trimmed; null when the prefix is missing or nothing is left. */
function pointer(f: FileInput, prefix: string): string | null {
  let b = f.head ?? (f.text === null ? null : new TextEncoder().encode(f.text.slice(0, 4096)));
  if (b === null) return null;
  b = b.subarray(0, 4096);
  const z = b.indexOf(0);
  if (z >= 0) b = b.subarray(0, z);
  const nl = b.indexOf(0x0a);
  if (nl >= 0) b = b.subarray(0, nl);
  let l = dec.decode(b).replace(/\r/g, '');
  if (prefix) { if (!l.startsWith(prefix)) return null; l = l.slice(prefix.length); }
  l = l.replace(/^[\t\n\v\f\r ]+|[\t\n\v\f\r ]+$/g, '');
  return l === '' ? null : l;
}

/** all: every file of the dropped folder (the root .git included); root: its top directory name ('' if none);
 *  home: whether the folder is treated as HOME (then "~/x" of an include is the folder's x); extra: texts of configs over
 *  the generic read limit, read by the caller up to GIT_CONFIG_MAX (see needsGitRead). */
export function gitDiscover(all: FileInput[], root: string, home: boolean, extra: Map<string, GitConfigText> = new Map()): GitDiscovery {
  const pre = root ? root + '/' : '';
  const rel = (p: string) => (root ? p.slice(pre.length) : p);
  const byRel = new Map(all.map((f) => [rel(f.relPath), f]));
  const dirs = parentDirs(all.map((f) => rel(f.relPath)));
  const dirname = (p: string) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');
  const isDir = (d: string) => d === '' || dirs.has(d);
  const sub = (d: string, n: string) => (d ? `${d}/${n}` : n);
  const errors: ScanError[] = [];
  const outside: string[] = [];
  const configs: FileInput[] = [];
  const texts = new Map<string, GitConfigText>();
  const seenCfg = new Set<string>();
  const hookDirs: string[] = [];
  const note = (what: string) => { if (!outside.includes(what)) outside.push(what); };
  // A path that a pointer names, resolved from the directory base like realpath (see the header): the path inside the
  //   folder ('' is the folder itself), 'outside' (noted), or null (a component is missing)
  const resolve = (base: string, p: string): string | null | 'outside' => {
    if (p.startsWith('/') || /^[A-Za-z]:[\\/]/.test(p)) return 'outside';
    const st = base ? base.split('/') : [];
    let up = 0; // levels above the top of the folder
    const segs = p.split('/');
    let end = segs.length - 1;
    while (end >= 0 && (segs[end] === '' || segs[end] === '.')) end--;
    for (let i = 0; i < segs.length; i++) {
      const s = segs[i]!;
      if (s === '' || s === '.') continue;
      if (s === '..') { if (up) up++; else if (st.length) st.pop(); else up = 1; continue; }
      if (up) {
        if (up === 1 && root && s === root) { up = 0; continue; }
        return 'outside';
      }
      st.push(s);
      if (i < end && !dirs.has(st.join('/'))) return null;
    }
    return up ? 'outside' : st.join('/');
  };
  const target = (from: string, p: string): string | null => {
    const t = resolve(dirname(from), p);
    if (t === 'outside') { note(p); return null; }
    return t;
  };
  const textOf = (f: FileInput): GitConfigText | null => (f.text !== null ? { text: f.text, sha256: f.sha256 } : extra.get(f.relPath) ?? null);
  const collect = (cfg: string, depth: number): void => {
    if (seenCfg.has(cfg)) return;
    seenCfg.add(cfg);
    const f = byRel.get(cfg)!;
    configs.push(f);
    const t = textOf(f);
    if (t) texts.set(f.relPath, t);
    else errors.push({ module: 'core', reason: `git_config_unread:${f.relPath}` });
    if (f.size > GIT_CONFIG_MAX) errors.push({ module: 'core', reason: `git_config_truncated:${f.relPath}` });
    if (depth >= 10) { errors.push({ module: 'core', reason: `git_include_too_deep:${f.relPath}` }); return; }
    for (const inc of t === null ? [] : gitIncludes(t.text)) {
      let r: string | null;
      if (inc.startsWith('~/')) { const h = home ? resolve('', inc.slice(2)) : 'outside'; r = h === 'outside' ? (note(inc), null) : h; }
      else r = target(cfg, inc);
      if (r !== null && byRel.has(r)) collect(r, depth + 1);
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
      const t = pointer(f, 'gitdir:');
      if (t === null) { errors.push({ module: 'core', reason: `gitfile_unparsed:${f.relPath}` }); continue; }
      const g = resolve(dirname(p), t);
      if (g === 'outside') { note(t); errors.push({ module: 'core', reason: `gitdir_outside_root:${f.relPath}` }); continue; }
      if (g === null || !isDir(g)) { errors.push({ module: 'core', reason: `gitdir_unresolved:${f.relPath}` }); continue; }
      gd = g;
    }
    let cd = gd;
    const cf = byRel.get(sub(gd, 'commondir'));
    if (cf) {
      const t = pointer(cf, '');
      const c = t === null ? null : resolve(gd, t);
      if (c !== null && c !== 'outside' && isDir(c)) cd = c;
      else { if (c === 'outside') note(t!); errors.push({ module: 'core', reason: `git_commondir_unresolved:${pre}${p}` }); }
    }
    const hd = sub(cd, 'hooks');
    if (dirs.has(hd) && !hookDirs.includes(pre + hd)) hookDirs.push(pre + hd);
    for (const c of [sub(gd, 'config'), sub(gd, 'config.worktree'), sub(cd, 'config'), sub(cd, 'config.worktree')]) if (byRel.has(c)) collect(c, 0);
  }
  return { configs, texts, hookDirs, errors, outside };
}

/** Configs gitDiscover found whose text the generic reader skipped for their size and that can be read (File kept). */
export function needsGitRead(g: GitDiscovery, extra: Map<string, GitConfigText>): FileInput[] {
  return g.configs.filter((f) => f.text === null && f.blob && f.readState === 'skipped-size' && !extra.has(f.relPath));
}

/** Every ancestor directory of the paths ('a/b/c' gives 'a/b' and 'a'); linear in the total path length: the walk up
 *  stops at the first directory already known (its ancestors are known too). */
export function parentDirs(paths: Iterable<string>): Set<string> {
  const dirs = new Set<string>();
  for (const p of paths) {
    for (let i = p.lastIndexOf('/'); i > 0; i = p.lastIndexOf('/', i - 1)) {
      const d = p.slice(0, i);
      if (dirs.has(d)) break;
      dirs.add(d);
    }
  }
  return dirs;
}

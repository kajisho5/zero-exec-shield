// Git config files read the way git reads them, the same parser as the CLI's ZES_GITCFG_AWK (git config.c: parse_config,
//   get_base_var, get_extended_base_var, get_value, parse_value). The text is what the browser decoded (TextDecoder has
//   removed one leading BOM, as git skips one). Lines end at LF only (CR LF is LF, a lone CR is whitespace; U+2028 is an
//   ordinary character), "#" / ";" start a comment, "[section]", "[section "sub"]" and "[section.sub]" may be followed on
//   the same line by another header or by a variable, names are case-insensitive (a quoted subsection is not), a value is
//   unquoted and unescaped (\n \t \b \\ \"), whitespace outside quotes becomes one space per character and is trimmed at
//   both ends, and "\" at the end of a line continues the value. Where git stops with "bad config line", the reader skips
//   to the next line and goes on, so it never reports less than git reads.

export interface GitConfigVar {
  /** 1-based line of the key */
  line: number;
  section: string;
  subsection: string;
  key: string;
  /** null for a key without "=" (git's implicit true) */
  value: string | null;
}

/** git's isspace (sane_ctype: space, tab, CR, LF); VT and FF are not whitespace for git. */
const isWs = (c: string) => c === ' ' || c === '\t' || c === '\r';
const KEYCH = /[A-Za-z0-9-]/;
const lower = (s: string) => s.replace(/[A-Z]+/g, (m) => m.toLowerCase());

export function gitConfigVars(text: string): GitConfigVar[] {
  const out: GitConfigVar[] = [];
  const lines = text.split('\n');
  let sec = '';
  let sub = '';
  // value state (a value that continues on the next line keeps it)
  let inVal = false;
  let key = '';
  let keyLine = 0;
  let v: string[] = [];
  let vlen = 0;
  let sp = 0;
  let quote = false;
  const pend = () => { for (; sp > 0; sp--) { v.push(' '); vlen++; } };
  const end = () => { out.push({ line: keyLine, section: sec, subsection: sub, key, value: v.join('') }); inVal = false; v = []; vlen = 0; sp = 0; quote = false; };
  // scans the value from p to the end of the line; returns true when it continues on the next line
  const scanValue = (L: string, p: number): boolean => {
    for (let i = p; i < L.length; i++) {
      const c = L[i]!;
      if (isWs(c) && !quote) { if (vlen) sp++; continue; }
      if (!quote && (c === '#' || c === ';')) break;
      pend();
      if (c === '\\') {
        if (i + 1 >= L.length) return true;
        let e = L[++i]!;
        if (e === 'n') e = '\n'; else if (e === 't') e = '\t'; else if (e === 'b') e = '\b';
        v.push(e); vlen++;
        continue;
      }
      if (c === '"') { quote = !quote; continue; }
      v.push(c); vlen++;
    }
    end();
    return false;
  };
  // the header that starts after "[" at p; the position after "]" or -1
  const header = (L: string, p: number): number => {
    let q = p;
    for (; q < L.length; q++) {
      const c = L[q]!;
      if (c === ']') {
        if (q === p) return -1;
        const name = lower(L.slice(p, q));
        const k = name.indexOf('.');
        if (k >= 0) { sec = name.slice(0, k); sub = name.slice(k + 1); } else { sec = name; sub = ''; }
        return q + 1;
      }
      if (isWs(c)) break;
      if (!/[A-Za-z0-9.-]/.test(c)) return -1;
    }
    if (q >= L.length || q === p) return -1;
    const name = lower(L.slice(p, q));
    while (q < L.length && isWs(L[q]!)) q++;
    if (q >= L.length || L[q] !== '"') return -1;
    const s: string[] = [];
    for (q++; q < L.length; q++) {
      const c = L[q]!;
      if (c === '"') break;
      if (c === '\\') { q++; if (q >= L.length) return -1; s.push(L[q]!); continue; }
      s.push(c);
    }
    if (q >= L.length || L[q + 1] !== ']') return -1;
    sec = name; sub = s.join('');
    return q + 2;
  };
  for (let ln = 0; ln < lines.length; ln++) {
    let L = lines[ln]!;
    if (L.endsWith('\r')) L = L.slice(0, -1);
    if (inVal) { inVal = scanValue(L, 0); continue; }
    for (let p = 0; p < L.length;) {
      const c = L[p]!;
      if (isWs(c)) { p++; continue; }
      if (c === '#' || c === ';') break;
      if (c === '[') { p = header(L, p + 1); if (p < 0) break; continue; }
      if (!/[A-Za-z]/.test(c)) break;
      let q = p + 1;
      while (q < L.length && KEYCH.test(L[q]!)) q++;
      key = lower(L.slice(p, q)); keyLine = ln + 1;
      while (q < L.length && (L[q] === ' ' || L[q] === '\t')) q++;
      if (q >= L.length) { out.push({ line: keyLine, section: sec, subsection: sub, key, value: null }); break; }
      if (L[q] !== '=') break;
      v = []; vlen = 0; sp = 0; quote = false;
      inVal = scanValue(L, q + 1);
      break;
    }
  }
  if (inVal) end();
  return out;
}

/** Whether git reads the value as a boolean (git_parse_maybe_bool: "", true / yes / on / false / no / off in any case,
 *  or an int of git_parse_int: base 0, unit k / m / g, int range; a leading 0 is octal there, so only 0 itself). */
export function gitBool(v: string): boolean {
  const l = lower(v);
  if (['', 'true', 'yes', 'on', 'false', 'no', 'off'].includes(l)) return true;
  const m = /^([-+]?)(0|[1-9][0-9]{0,9})([kmg]?)$/.exec(l);
  if (!m) return false;
  const n = Number(m[2]) * (m[3] === 'k' ? 1024 : m[3] === 'm' ? 1048576 : m[3] === 'g' ? 1073741824 : 1);
  return m[1] === '-' ? n <= 2147483648 : n <= 2147483647;
}

export interface S26Hit { key: 'fsmonitor' | 'sshcommand' | 'hookspath'; lines: number[] }

/** §26 of one Git config (the CLI's S26_VARS_AWK): every assignment counts, not only the last one (a later file of the
 *  chain can undo a "fsmonitor = false"). core.fsmonitor runs a command unless the value is a Git boolean; sshCommand and
 *  hooksPath are reported for any value. The key is matched in every section. Up to 64 lines each. */
export function s26Hits(text: string): S26Hit[] {
  const hits = new Map<S26Hit['key'], number[]>();
  for (const x of gitConfigVars(text)) {
    if (x.value === null) continue;
    const k = x.key === 'fsmonitor' ? (gitBool(x.value) ? null : 'fsmonitor') : x.key === 'sshcommand' || x.key === 'hookspath' ? x.key : null;
    if (!k) continue;
    const l = hits.get(k) ?? [];
    if (l.length < 64) l.push(x.line);
    hits.set(k, l);
  }
  return (['fsmonitor', 'sshcommand', 'hookspath'] as const).filter((k) => hits.has(k)).map((k) => ({ key: k, lines: hits.get(k)! }));
}

/** include.path / includeIf "<condition>".path values in document order (conditions are not evaluated; [include "x"] too). */
export function gitIncludes(text: string): string[] {
  return gitConfigVars(text).filter((x) => (x.section === 'include' || x.section === 'includeif') && x.key === 'path' && x.value).map((x) => x.value!);
}

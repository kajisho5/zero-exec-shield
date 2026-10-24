// A TOML tokenizer that reads the command / args of MCP servers from the .codex/config.toml of Codex CLI.
// A port that works by the same rules as the CLI (codex_toml_mcp_commands in zes-scan.sh).
//   Stage 1: tokenizes the whole file and collects every value as { type, key path, value }.
//     Supports: table headers [a . "b" . 'c'] / [[array tables]], dotted keys, basic strings (escapes decoded),
//           literal strings, multi-line strings (""" / '''), nested arrays (multi-line, comments and trailing commas allowed),
//           inline tables (may nest), other scalars (numbers, booleans, dates/times)
//     Control characters in values (newlines, tabs etc. after decoding) are replaced by spaces (to match them as a single command line)
//   Stage 2: collects mcp_servers.<name>.command / .args / .url and groups them per server.
//   Syntax errors and servers whose command is not a string or that have neither command nor url put a reason into problems
//   (the caller records them in errors[]; unreadable configs are not treated as 0 hits).
//   On a syntax error, values read before the error position are still used, as in the CLI.

export interface CodexServer { name: string; command: string; args: string[] }
export interface CodexTomlResult { servers: CodexServer[]; problems: string[] }

type Rec = { t: 's' | 'a' | 't' | 'o'; p: string[]; v: string };

class TomlError extends Error {}

/** Maximum nesting of arrays and inline tables. Codex CLI reads its config with the Rust toml crate (0.9), whose parser stops
 *  at a depth above 80 ("cannot recurse further; max recursion depth met": toml_parser RecursionGuard, LIMIT = 80). The CLI
 *  (codex_toml_mcp_commands) uses the same limit. */
export const TOML_MAX_DEPTH = 80;

function tokenize(src: string, recs: Rec[]): void {
  // Equivalent of text_lines: drop a leading BOM and the CR at the end of each line
  const S = src.replace(/^﻿/, '').replace(/\r(?=\n|$)/g, '');
  const n = S.length;
  let i = 0;
  let line = 1;
  const perr = (why: string): never => { throw new TomlError(`parse_error:${why}:line${line}`); };
  const ch = (k = 0) => S[i + k] ?? '';
  const skipWs = () => { while (i < n && (ch() === ' ' || ch() === '\t')) i++; };
  const skipWsNl = () => {
    while (i < n) {
      const c = ch();
      if (c === ' ' || c === '\t') i++;
      else if (c === '\n') { line++; i++; }
      else if (c === '#') { while (i < n && ch() !== '\n') i++; }
      else break;
    }
  };
  const eol = () => {
    skipWs();
    if (ch() === '#') while (i < n && ch() !== '\n') i++;
    if (i >= n) return;
    if (ch() !== '\n') perr('trailing_characters');
    line++; i++;
  };
  const cpChar = (cp: number) => (cp < 32 || cp === 127 ? ' ' : String.fromCodePoint(cp));
  // Decode one character starting right after the backslash (i is the escape character)
  const esc = (): string => {
    const c = ch(); i++;
    if (c === '"' || c === '\\') return c;
    if ('ntrbfe'.includes(c) && c !== '') return ' ';
    if (c === 'u' || c === 'U' || c === 'x') {
      const L = c === 'u' ? 4 : c === 'U' ? 8 : 2;
      const h = S.slice(i, i + L);
      if (h.length !== L || !/^[0-9a-fA-F]+$/.test(h)) perr('bad_escape');
      const cp = parseInt(h, 16);
      if (cp > 0x10ffff) perr('bad_escape');
      i += L;
      return cpChar(cp);
    }
    return perr('bad_escape');
  };
  const strch = (c: string) => { if (c === '\t') return ' '; if (c < ' ' && c !== '') perr('control_character'); return c; };
  const bstr = () => {
    i++; let out = '';
    for (;;) {
      if (i >= n) perr('unterminated_string');
      const c = ch();
      if (c === '"') { i++; return out; }
      if (c === '\n') perr('newline_in_string');
      if (c === '\\') { i++; out += esc(); continue; }
      out += strch(c); i++;
    }
  };
  const lstr = () => {
    i++; let out = '';
    for (;;) {
      if (i >= n) perr('unterminated_string');
      const c = ch();
      if (c === "'") { i++; return out; }
      if (c === '\n') perr('newline_in_string');
      out += strch(c); i++;
    }
  };
  // Multi-line string. Up to 2 delimiter characters may appear right before the closing delimiter
  const mlstr = (q: string) => {
    i += 3;
    if (ch() === '\n') { line++; i++; }
    let out = '';
    for (;;) {
      if (i >= n) perr('unterminated_string');
      const c = ch();
      if (c === q && ch(1) === q && ch(2) === q) {
        let k = 0; while (ch(k) === q) k++;
        if (k > 5) perr('bad_multiline_string');
        out += q.repeat(k - 3);
        i += k; return out;
      }
      if (c === '\\' && q === '"') {
        let j = 1; while (ch(j) === ' ' || ch(j) === '\t') j++;
        if (ch(j) === '\n') {
          i += j;
          while (i < n && (ch() === ' ' || ch() === '\t' || ch() === '\n')) { if (ch() === '\n') line++; i++; }
          continue;
        }
        i++; out += esc(); continue;
      }
      if (c === '\n') { line++; out += ' '; i++; continue; }
      out += strch(c); i++;
    }
  };
  // Key (dotted, quoted keys allowed)
  const key = (): string[] => {
    const ks: string[] = [];
    for (;;) {
      skipWs();
      const c = ch();
      let k: string;
      if (c === '"') { if (ch(1) === '"' && ch(2) === '"') perr('bad_key'); k = bstr(); }
      else if (c === "'") { if (ch(1) === "'" && ch(2) === "'") perr('bad_key'); k = lstr(); }
      else { k = ''; while (i < n && /[A-Za-z0-9_-]/.test(ch())) { k += ch(); i++; } if (k === '') perr('bad_key'); }
      ks.push(k);
      skipWs();
      if (ch() === '.') { i++; continue; }
      return ks;
    }
  };
  const rec = (t: Rec['t'], p: string[], v: string) => { recs.push({ t, p, v }); };
  // Arrays and inline tables nest at most TOML_MAX_DEPTH deep (the limit of the TOML parser of Codex CLI); deeper is a parse
  // error, as in the CLI
  let depth = 0;
  const value = (p: string[]): void => {
    const c = ch();
    if ((c === '[' || c === '{') && ++depth > TOML_MAX_DEPTH) perr('nesting_too_deep');
    if (c === '"') { rec('s', p, ch(1) === '"' && ch(2) === '"' ? mlstr('"') : bstr()); return; }
    if (c === "'") { rec('s', p, ch(1) === "'" && ch(2) === "'" ? mlstr("'") : lstr()); return; }
    if (c === '[') {
      i++; let idx = 0; rec('a', p, '');
      for (;;) {
        skipWsNl(); if (i >= n) perr('unterminated_array');
        if (ch() === ']') { i++; depth--; return; }
        value([...p, String(idx)]); idx++;
        skipWsNl();
        const d = ch();
        if (d === ',') { i++; continue; }
        if (d === ']') { i++; depth--; return; }
        perr('bad_array');
      }
    }
    if (c === '{') {
      i++; rec('t', p, ''); skipWsNl();
      if (ch() === '}') { i++; depth--; return; }
      for (;;) {
        skipWsNl();
        const kp = [...p, ...key()];
        skipWs(); if (ch() !== '=') perr('bad_inline_table'); i++; skipWs();
        value(kp); skipWsNl();
        const d = ch();
        if (d === ',') { i++; continue; }
        if (d === '}') { i++; depth--; return; }
        perr('bad_inline_table');
      }
    }
    let t = '';
    while (i < n && /[A-Za-z0-9_+.:-]/.test(ch())) { t += ch(); i++; }
    if (/^\d{4}-\d\d-\d\d$/.test(t) && ch() === ' ' && /[0-9]/.test(ch(1))) { i++; while (i < n && /[0-9:.Zz+-]/.test(ch())) i++; }
    if (t === '') perr('bad_value');
    rec('o', p, t);
  };

  let tbl: string[] = [];
  const at = new Map<string, number>();
  for (;;) {
    skipWsNl(); if (i >= n) break;
    if (ch() === '[') {
      const arr = ch(1) === '[';
      i += arr ? 2 : 1;
      let p = key();
      skipWs();
      if (arr) {
        if (ch() !== ']' || ch(1) !== ']') perr('bad_table_header');
        i += 2;
        const k = p.join('\u001c');
        const x = at.get(k) ?? 0;
        at.set(k, x + 1);
        p = [...p, String(x)];
      } else {
        if (ch() !== ']') perr('bad_table_header');
        i++;
      }
      tbl = p; rec('t', p, ''); eol(); continue;
    }
    const p = [...tbl, ...key()];
    skipWs(); if (ch() !== '=') perr('expected_equals'); i++; skipWs();
    value(p); eol();
  }
}

export function parseCodexToml(text: string): CodexTomlResult {
  const recs: Rec[] = [];
  const problems: string[] = [];
  try { tokenize(text, recs); } catch (e) {
    if (!(e instanceof TomlError)) throw e;
    problems.push(e.message);
  }
  const order: string[] = [];
  const seen = new Set<string>();
  const cmd = new Map<string, string>();
  const args = new Map<string, string[]>();
  const bad = new Map<string, string>();
  const hasUrl = new Set<string>();
  for (const { t, p, v } of recs) {
    if (p[0] !== 'mcp_servers') continue;
    if (p.length === 1) { if (t !== 't') problems.push('unexpected_value:mcp_servers'); continue; }
    const nm = p[1]!;
    if (!seen.has(nm)) { seen.add(nm); order.push(nm); }
    if (p.length === 2) { if (t !== 't') problems.push(`unexpected_value:${nm}`); continue; }
    if (p[2] === 'command' && p.length === 3) { if (t === 's') cmd.set(nm, v); else bad.set(nm, 'unparsed_command'); continue; }
    if (p[2] === 'args') {
      // args accepts both an array (per element) and a string (one argument)
      if (t === 's' && (p.length === 3 || p.length === 4)) { const a = args.get(nm); if (a) a.push(v); else args.set(nm, [v]); }
      else if (!(p.length === 3 && t === 'a')) bad.set(nm, 'unparsed_args');
      continue;
    }
    if (p[2] === 'url' && p.length === 3) hasUrl.add(nm);
  }
  const servers: CodexServer[] = [];
  for (const nm of order) {
    const c = cmd.get(nm) ?? '';
    if (c !== '') servers.push({ name: nm, command: c, args: args.get(nm) ?? [] });
    if (bad.has(nm)) problems.push(`${bad.get(nm)}:${nm}`);
    else if (c === '' && !hasUrl.has(nm)) problems.push(`no_command:${nm}`);
  }
  return { servers, problems };
}

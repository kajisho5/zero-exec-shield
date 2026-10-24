// The lenient reading of agent / MCP JSON (§17), the same reader as the CLI's ZES_JSONW_AWK. It is used when JSON.parse and
//   parseJsonc both fail, so that one behaviour holds on both sides: the CLI reads these files with jq, which accepts
//   01, NaN, Infinity, +1, .5, 1. and several documents in a row, and JSON.parse accepts lone surrogate escapes and any
//   depth (jq 1.7 stops at 256). A file that either reader (or an agent) reads is read here, and a dangerous command in it
//   is reported (the safer behaviour).
//   Accepted: JSON plus comments (// and /* */), trailing commas, any literal (a run of characters other than whitespace,
//   structure, quotes and "/"), several documents, lone surrogate escapes (U+FFFD), any depth. A control character in a
//   string, an unknown escape, an unbalanced structure or a missing ":" / "," fails (null).
//   Result: every object that has a "command" member (the last member of each name counts), in the order the objects end,
//   with command (its string, or the strings and literals inside it joined by " "), args (the strings and literals inside
//   it joined by " "; "" for null / false) and its path; jsonc is true when a comment or a trailing comma was read.

/** path is null below depth 256 (the depth jq reads; longer paths would cost time quadratic in the depth): no locator */
export interface LenientCmd {
  path: (string | number)[] | null;
  /** the hook entry /hooks/<Event>/<i> that holds the object (its path), at any depth; null outside one */
  entry: (string | number)[] | null;
  command: string; commandIsString: boolean; args: string;
}

type Frame = {
  t: 'o' | 'a'; path: (string | number)[] | null; entry: (string | number)[] | null; key: string; idx: number;
  hasCmd: boolean; cmdStr: boolean; cmd: string; args: string; cap: '' | 'command' | 'args'; capText: string[];
};

export function lenientJson(text: string): { cmds: LenientCmd[]; jsonc: boolean } | null {
  const st: Frame[] = [];
  const caps: Frame[] = [];
  const cmds: LenientCmd[] = [];
  // what comes next: v a value, k a member name, : a colon, , a comma or the end of the container (a string: set in closures)
  let ex: string = 'v';
  let jsonc = false;
  let values = 0;
  const n = text.length;
  const scalar = (s: string, isStr: boolean, lit: string) => {
    for (let k = caps.length - 1; k >= 0 && k >= caps.length - 64; k--) caps[k]!.capText.push(s);
    value(isStr ? 's' : 'l', s, lit);
  };
  const value = (kind: 's' | 'l' | 'c', s: string, lit: string) => {
    values++;
    const top = st[st.length - 1];
    if (!top) { ex = 'v'; return; }
    if (top.t === 'a') { top.idx++; ex = ','; return; }
    if (top.cap) {
      const joined = top.capText.join(' ');
      if (top.cap === 'command') { top.hasCmd = true; top.cmdStr = kind === 's'; top.cmd = kind === 's' ? s : joined; }
      else top.args = kind === 'l' && (lit === 'null' || lit === 'false') ? '' : joined;
      top.cap = ''; top.capText = []; caps.pop();
    }
    ex = ',';
  };
  const open = (t: 'o' | 'a') => {
    const top = st[st.length - 1];
    const path = !top ? [] : top.path === null || st.length >= 256 ? null : top.t === 'a' ? [...top.path, top.idx] : [...top.path, top.key];
    // an element of the array of a member of the top-level "hooks" object of a document is a hook entry
    const entry = top?.entry ?? (st.length === 3 && st[0]!.t === 'o' && st[0]!.key === 'hooks' && st[1]!.t === 'o' && st[2]!.t === 'a' ? ['hooks', st[1]!.key, st[2]!.idx] : null);
    st.push({ t, path, entry, key: '', idx: 0, hasCmd: false, cmdStr: false, cmd: '', args: '', cap: '', capText: [] });
    ex = t === 'o' ? 'k' : 'v';
  };
  const close = (t: 'o' | 'a'): boolean => {
    const top = st[st.length - 1];
    if (!top || top.t !== t) return false;
    if (t === 'o' && top.hasCmd) cmds.push({ path: top.path, entry: top.entry, command: top.cmd, commandIsString: top.cmdStr, args: top.args });
    st.pop();
    value('c', '', '');
    return true;
  };
  let inComment = false;
  for (let i = 0; i < n; i++) {
    const c = text[i]!;
    if (inComment) { if (c === '*' && text[i + 1] === '/') { inComment = false; i++; } continue; }
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n') continue;
    if (c === '/') {
      jsonc = true;
      if (text[i + 1] === '/') { while (i < n && text[i] !== '\n') i++; continue; }
      if (text[i + 1] === '*') { inComment = true; i++; continue; }
      return null;
    }
    if (c === '"') {
      const out: string[] = [];
      let j = i + 1;
      let ok = false;
      for (; j < n; j++) {
        const d = text[j]!;
        if (d === '"') { ok = true; break; }
        if (d < ' ') break;
        if (d !== '\\') { out.push(d); continue; }
        const e = text[j + 1];
        if (e === 'u') {
          const h = text.slice(j + 2, j + 6);
          if (!/^[0-9A-Fa-f]{4}$/.test(h)) break;
          let cp = parseInt(h, 16);
          j += 5;
          if (cp >= 0xd800 && cp < 0xdc00 && text.slice(j + 1, j + 3) === '\\u' && /^[dD][c-fC-F][0-9A-Fa-f]{2}$/.test(text.slice(j + 3, j + 7))) {
            cp = 0x10000 + (cp - 0xd800) * 1024 + parseInt(text.slice(j + 3, j + 7), 16) - 0xdc00; j += 6;
          } else if (cp >= 0xd800 && cp < 0xe000) cp = 0xfffd;
          out.push(String.fromCodePoint(cp));
        } else if (e === '"' || e === '\\' || e === '/') { out.push(e); j++; }
        else if (e === 'b') { out.push('\b'); j++; } else if (e === 'f') { out.push('\f'); j++; }
        else if (e === 'n') { out.push('\n'); j++; } else if (e === 'r') { out.push('\r'); j++; } else if (e === 't') { out.push('\t'); j++; }
        else break;
      }
      if (!ok) return null;
      const s = out.join('');
      i = j;
      const top = st[st.length - 1];
      if (ex === 'k' && top) { top.key = s; ex = ':'; continue; }
      if (ex !== 'v') return null;
      scalar(s, true, '');
      continue;
    }
    if (c === ':') {
      const top = st[st.length - 1];
      if (ex !== ':' || !top) return null;
      ex = 'v';
      if (top.key === 'command' || top.key === 'args') { top.cap = top.key; top.capText = []; caps.push(top); }
      continue;
    }
    if (c === ',') { if (ex !== ',') return null; ex = st[st.length - 1]!.t === 'o' ? 'k' : 'v'; continue; }
    if (c === '{' || c === '[') { if (ex !== 'v') return null; open(c === '{' ? 'o' : 'a'); continue; }
    if (c === '}' || c === ']') {
      const t = c === '}' ? 'o' : 'a';
      const top = st[st.length - 1];
      if (ex === 'k' || (ex === 'v' && t === 'a')) { if (top && top.t === t && (top.idx > 0 || top.key !== '')) jsonc = true; }
      else if (ex !== ',') return null;
      if (!close(t)) return null;
      continue;
    }
    let j = i;
    while (j < n && !/[ \t\r\n{}[\]:,"/]/.test(text[j]!)) j++;
    if (ex !== 'v' || j === i) return null;
    const lit = text.slice(i, j);
    i = j - 1;
    scalar(lit, false, lit);
  }
  // a text without any value is not read (an empty file, as the browser sees a symlink, stays unparsed: fail-closed)
  if (st.length || inComment || !values) return null;
  return { cmds, jsonc };
}

/** JSON text with the \u escapes of printable ASCII other than " and \ decoded (the CLI's json_unescape_ascii): the
 *  fail-closed view of a file that cannot be parsed. */
export function unescapeAscii(text: string): string {
  return text.replace(/\\u00([2-7][0-9A-Fa-f])/g, (m, h: string) => { const c = parseInt(h, 16); return c === 0x22 || c === 0x5c || c === 0x7f ? m : String.fromCharCode(c); });
}

/** The text the raw-text checks of JSON files read (the CLI's json_view): the parsed document serialized (keys and strings
 *  decoded), or the unescaped text when it does not parse. */
export function jsonView(text: string, parseJsonc: (t: string) => unknown): string {
  try { return JSON.stringify(JSON.parse(text)); } catch { /* JSONC */ }
  try { return JSON.stringify(parseJsonc(text)); } catch { /* raw */ }
  return unescapeAscii(text);
}

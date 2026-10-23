// §21 / §22 / §38 GitHub Actions、§24 / §42 ブラウザ拡張
import { pathMatch, push, readable, type RuleCtx } from '../context';
import type { UsesRef } from '../types';
import { clip, dirname } from '../util';

const lead = (x: string) => (/^[ \t]*/.exec(x)?.[0] ?? '').length;
/** ノード属性（アンカー &x・タグ !!str / !tag）を先頭から除く（CLI yaml_flatten の props と同じ） */
const yamlProps = (v: string) => { let x = v; for (let m = /^(&[^ \t]+|![^ \t]*)([ \t]+|$)/.exec(x); m; m = /^(&[^ \t]+|![^ \t]*)([ \t]+|$)/.exec(x)) x = x.slice(m[0].length); return x; };
const yamlAlias = (v: string) => /^\*[^ \t,\]}]+[ \t]*(#.*)?$/.test(v);
/** 引用符の外側の括弧の深さ（[ { と ] }） */
function yamlDepth(x: string): number {
  let d = 0; let q = '';
  for (let i = 0; i < x.length; i++) {
    const c = x[i]!;
    if (q) { if (c === '\\' && q === '"') { i++; continue } if (c === q) q = ''; continue; }
    if (c === '"' || c === "'") { q = c; continue; }
    if (c === '#' && (i === 0 || /[ \t]/.test(x[i - 1]!))) break;
    if (c === '[' || c === '{') d++; else if (c === ']' || c === '}') d--;
  }
  return d;
}
/** 引用符の外側の行末コメントを除く */
function yamlNoComment(x: string): string {
  let q = '';
  for (let i = 0; i < x.length; i++) {
    const c = x[i]!;
    if (q) { if (c === '\\' && q === '"') { i++; continue } if (c === q) q = ''; continue; }
    if (c === '"' || c === "'") { q = c; continue; }
    if (c === '#' && (i === 0 || /[ \t]/.test(x[i - 1]!))) return x.slice(0, i);
  }
  return x;
}

/**
 * YAML の 1 段目の正規化（CLI yaml_flatten と同じ）。ノード属性（&anchor / !tag）を除き、フロー列（"steps: [ {uses: a}, … ]"。
 * 複数行を含む）を 1 要素 1 行のブロック列に展開する。エイリアス（*x / <<: *x）は解決せず "#ZES-YAML-ALIAS" 行を出す。
 * ブロックスカラー（run: | 等）の中身はそのまま通す。
 */
export function yamlFlatten(yaml: string): string[] {
  const src = yaml.replace(/^\uFEFF/, '').split('\n').map((l) => l.replace(/\r$/, ''));
  if (src.length && src[src.length - 1] === '') src.pop();
  const out: string[] = [];
  let inblk = false; let bind = 0; let acc = ''; let apre = ''; let aind = 0;
  const item = (el0: string, ind: string) => {
    let el = el0.replace(/^[ \t]+/, '').replace(/[ \t]+$/, '');
    if (el === '') return;
    el = yamlProps(el);
    if (yamlAlias(el)) out.push('#ZES-YAML-ALIAS');
    out.push(ind + '- ' + el);
  };
  const flow = (body0: string, ind: string) => {
    const body = body0.replace(/^[ \t]*\[/, '').replace(/\][ \t]*(#.*)?$/, '');
    let d = 0; let q = ''; let el = '';
    for (let i = 0; i < body.length; i++) {
      const c = body[i]!;
      if (q) { el += c; if (c === '\\' && q === '"') { i++; el += body[i] ?? ''; continue } if (c === q) q = ''; continue; }
      if (c === '"' || c === "'") { q = c; el += c; continue; }
      if (c === '[' || c === '{') d++; else if (c === ']' || c === '}') d--;
      if (c === ',' && d === 0) { item(el, ind); el = ''; continue; }
      el += c;
    }
    item(el, ind);
  };
  const pad = (n: number) => ' '.repeat(n);
  for (const raw of src) {
    let line = raw;
    if (inblk) { if (/^[ \t]*$/.test(line) || lead(line) > bind) { out.push(line); continue; } inblk = false; }
    if (acc !== '') {
      acc += ' ' + yamlNoComment(line).replace(/^[ \t]+/, '');
      if (yamlDepth(acc) <= 0) { out.push(apre); flow(acc, pad(aind + 2)); acc = ''; }
      continue;
    }
    let pre = '';
    const dm = /^[ \t]*-([ \t]+|$)/.exec(line);
    if (dm) {
      pre = dm[0];
      const rest = yamlProps(line.slice(pre.length));
      if (yamlAlias(rest)) { out.push('#ZES-YAML-ALIAS'); out.push(pre + rest); continue; }
      line = pre + rest;
    }
    const ki = pre.length || lead(line);
    const km = /^[ \t]*(-[ \t]+)?["']?[A-Za-z0-9_.$<-]+["']?:([ \t]+|$)/.exec(line);
    if (!km) { out.push(line); continue; }
    const kpre = km[0];
    const v = yamlProps(line.slice(kpre.length));
    if (yamlAlias(v) || /<<:[ \t]*$/.test(kpre)) out.push('#ZES-YAML-ALIAS');
    if (/^[|>][-+0-9]*[ \t]*(#.*)?$/.test(v)) { out.push(kpre + v); inblk = true; bind = ki; continue; }
    if (v.startsWith('[')) {
      if (yamlDepth(v) > 0) { acc = yamlNoComment(v); apre = kpre; aind = ki; continue; }
      out.push(kpre); flow(v, pad(ki + 2)); continue;
    }
    out.push(kpre + v);
  }
  if (acc !== '') { out.push(apre); flow(acc, pad(aind + 2)); }
  return out;
}

/** エイリアス（*x）を含むか（CLI は errors[] に yaml_alias_unresolved を記録する） */
export const yamlHasAlias = (yaml: string) => yamlFlatten(yaml).includes('#ZES-YAML-ALIAS');

/**
 * ワークフロー本文の正規化（CLI workflow_text と同じ）。yamlFlatten の後、値が次行以降に続くキーを 1 行に畳む。
 *   - ブロックスカラー（"key: >-" / "key: |" 等）: より深くインデントされた後続行を全て空白区切りで連結
 *   - 値が空のキーの後にプレーンスカラーが続く場合（"- uses:" の次行に値）: マッピング/シーケンスでない
 *     より深い後続行を連結（YAML のプレーンスカラーの複数行折り返し）
 * run: | の中に書かれた "uses: …" はこの畳み込みで run: の値の一部になり、ステップとして数えない。
 */
export function workflowText(yaml: string): string[] {
  const src = yamlFlatten(yaml);
  const out: string[] = [];
  let pend = '';
  let pind = 0;
  let blk = false;
  let acc = '';
  const KEY_ONLY = /^\s*(-\s+)?["']?[A-Za-z0-9_.$-]+["']?:\s*([>|][-+0-9]*)?\s*(#.*)?$/;
  const NODE = /^\s*(-(\s|$)|["']?[A-Za-z0-9_.$-]+["']?:(\s|$))/;
  for (const line of src) {
    if (pend !== '') {
      if (/^\s*$/.test(line) || (!blk && /^\s*#/.test(line))) continue;
      const lead = (/^\s*/.exec(line)?.[0] ?? '').length;
      if (lead > pind && (blk || !NODE.test(line))) {
        let v = line.replace(/^\s+/, '');
        if (!blk) v = v.replace(/\s+#.*$/, '');
        v = v.replace(/\s+$/, '');
        acc += (acc === '' ? '' : ' ') + v;
        continue;
      }
      out.push(pend + (acc !== '' ? ' ' + acc : ''));
      pend = ''; acc = '';
    }
    if (KEY_ONLY.test(line)) {
      pind = (/^\s*/.exec(line)?.[0] ?? '').length;
      if (/^\s*-\s/.test(line)) pind = line.length - line.replace(/^\s*-\s+/, '').length - 1;
      pend = line.replace(/\s*(#.*)?$/, '');
      blk = /:\s*[>|][-+0-9]*$/.test(pend);
      pend = pend.replace(/\s*[>|][-+0-9]*$/, '');
      acc = '';
      continue;
    }
    out.push(line);
  }
  if (pend !== '') out.push(pend + (acc !== '' ? ' ' + acc : ''));
  return out;
}

/** actions/checkout ステップごとの ref 種別（CLI §21 と同じ判定。入力は workflowText で正規化した行）。 */
export function checkoutRefs(yaml: string): ('noref' | 'prhead' | 'otherref' | 'exprref')[] {
  const out: ('noref' | 'prhead' | 'otherref' | 'exprref')[] = [];
  let inChk = false;
  let ind = 0;
  let ref: 'prhead' | 'otherref' | 'exprref' | '' = '';
  const flush = () => { if (inChk) out.push(ref === '' ? 'noref' : ref); inChk = false; ref = ''; };
  // ref はブロックマッピング（行頭の ref:）とフローマッピング（{ ref: … } / , ref: …）の両方を見る
  const getRef = (s: string) => {
    const m = /^\s*ref:/.exec(s) ?? /[{,]\s*ref:/.exec(s);
    if (!m) return;
    let r = s.slice(m.index + m[0].length).replace(/^\s*/, '');
    if (/^["']/.test(r)) {
      const q = r[0]!;
      r = r.slice(1);
      const k = r.indexOf(q);
      if (k >= 0) r = r.slice(0, k);
    } else {
      r = r.replace(/[,}].*$/, '');
    }
    // 正規化: 小文字化・空白除去・添字表記（github.event['pull_request']['head'] / ["…"]）をドット表記に
    r = r.toLowerCase().replace(/[ \t]/g, '').replace(/\[["']/g, '.').replace(/["']\]/g, '');
    if (/github\.(event\.pull_request\.(head|merge_commit_sha|number)|head_ref|event\.number)|refs\/pull\//.test(r)) ref = 'prhead';
    // ベース側の式（base.sha / base.ref / base_ref / github.sha / github.ref / default_branch）だけなら PR 由来ではない
    else if (r.replace(/\$\{\{(github\.event\.pull_request\.base\.(sha|ref)|github\.base_ref|github\.sha|github\.ref|github\.event\.repository\.default_branch)\}\}/g, '').includes('${{')) ref = 'exprref'; // それ以外の式は PR 由来でないと確認できない（最低 HIGH）
    else ref = 'otherref';
  };
  for (const line of workflowText(yaml)) {
    const lead = (/^\s*/.exec(line)?.[0] ?? '').length;
    // 引用符付き（uses: "actions/checkout@v4"）・所有者名の大文字小文字違い・フローマッピングのステップも対象
    if (/^\s*(-\s+)?(\{([^}#]*,)?\s*)?uses:\s*["']?actions\/checkout@/.test(line.toLowerCase())) {
      flush(); inChk = true; ind = lead;
      const at = line.lastIndexOf('actions/checkout@');
      getRef(at < 0 ? line : line.slice(at + 'actions/checkout@'.length));
      continue;
    }
    if (!inChk) continue;
    if (/^\s*-\s/.test(line) && lead <= ind) { flush(); continue; }
    getRef(line);
  }
  flush();
  return out;
}

/** §22 の uses: 参照（CLI と同じく正規化後の各行の先頭のステップ/フローマッピングの uses: のみ。重複は除く）。 */
export function usesRefs(yaml: string): string[] {
  const seen = new Set<string>();
  for (const line of workflowText(yaml)) {
    const m = /^[\s-]*(\{([^}#]*,)?\s*)?uses:\s*["']?[^"'\s#,}]+/.exec(line);
    if (!m) continue;
    seen.add(m[0].replace(/.*uses:\s*["']?/, ''));
  }
  return [...seen];
}

export function actionsRules(ctx: RuleCtx): void {
  ctx.checks.add('s21-prtarget').add('s21-cache').add('s21-writeall').add('s22-pinning').add('s38-secrets');
  const compromised = ctx.ioc.github_actions.known_compromised;
  // CLI check_s38: github_actions.secrets_ref_threshold (10 when missing)
  const th = ctx.ioc.github_actions['secrets_ref_threshold'];
  const threshold = typeof th === 'number' ? th : 10;
  for (const f of pathMatch(ctx, /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$|(^|\/)action\.ya?ml$/)) {
    const y = f.text;
    const isWorkflow = /\.github\/workflows\//.test(f.relPath);
    const prTarget = /(^|[^A-Za-z0-9_])pull_request_target([^A-Za-z0-9_]|$)/.test(y);
    // 式の文脈名は大文字小文字を区別しない（${{ SECRETS.X }} / ${{ toJSON(secrets) }} / secrets['X'] も secrets 参照）
    if (isWorkflow && prTarget && /actions\/checkout@/i.test(y) && /\$\{\{([^}\n]*[^A-Za-z0-9_.\n])?secrets([\][.\s)]|$)/im.test(y)) {
      const refs = checkoutRefs(y);
      if (refs.includes('prhead')) {
        push(ctx, { level: 'CRITICAL', module: '§21', campaign: 'ghostaction-oct2026', path: f.relPath, code: 's21.pwn_request', ruleId: 's21-prtarget:prhead', evidenceSha: f.sha256, kind: 'gha.pwn_request' });
      }
      if (refs.includes('noref')) {
        push(ctx, { level: 'HIGH', module: '§21', campaign: 'ghostaction-oct2026', path: f.relPath, code: 's21.prt_checkout_base', ruleId: 's21-prtarget:noref', evidenceSha: f.sha256, kind: 'gha.pwn_request' });
      }
      if (refs.includes('exprref')) {
        push(ctx, { level: 'HIGH', module: '§21', campaign: 'ghostaction-oct2026', path: f.relPath, code: 's21.prt_checkout_expr', ruleId: 's21-prtarget:exprref', evidenceSha: f.sha256, kind: 'gha.pwn_request' });
      }
    }
    if (/key:.*github\.event\.pull_request\.number/.test(y)) {
      push(ctx, { level: 'HIGH', module: '§21', campaign: 'ghostaction-oct2026', path: f.relPath, code: 's21.cache_pr_key', ruleId: 's21-cache', evidenceSha: f.sha256 });
    }
    if (/^\s*permissions:\s*write-all/m.test(y)) {
      push(ctx, { level: 'HIGH', module: '§21', campaign: 'ghostaction-oct2026', path: f.relPath, code: 's21.write_all', ruleId: 's21-writeall', evidenceSha: f.sha256 });
    }
    if (isWorkflow && yamlHasAlias(y)) ctx.errors.push({ module: '§21', reason: `yaml_alias_unresolved:${f.relPath}` });
    const n = new Set([...y.matchAll(/secrets\.([A-Za-z0-9_]+)/gi)].map((m) => m[1]!.toLowerCase())).size;
    if (n > threshold) push(ctx, { level: 'HIGH', module: '§38', campaign: 'ghostaction-oct2026', path: f.relPath, code: 's38.many_secrets', params: { n, threshold }, ruleId: 's38-secrets', evidenceSha: f.sha256 });
    if (/tojson\(\s*secrets\s*(\.\s*\*\s*)?\)/i.test(y)) push(ctx, { level: 'CRITICAL', module: '§38', campaign: 'ghostaction-oct2026', path: f.relPath, code: 's38.tojson_secrets', ruleId: 's38-tojson', evidenceSha: f.sha256 });

    const uses: UsesRef[] = [];
    // 正規化後の各行の uses:（フローマッピング・次行の値・ブロックスカラーを含む。run: の中の文字列は数えない）
    for (const ref of usesRefs(y)) {
      if (ref.startsWith('./') || ref.startsWith('docker://')) { uses.push({ ref: clip(ref), kind: 'local' }); continue; }
      const at = ref.lastIndexOf('@');
      if (at < 0) {
        uses.push({ ref: clip(ref), kind: 'tag' });
        push(ctx, { level: 'HIGH', module: '§22', campaign: 'ghostaction-oct2026', path: f.relPath, code: 's22.no_version', params: { ref }, ruleId: `s22-pinning:${ref}`, evidenceSha: f.sha256, kind: 'gha.unpinned' });
        continue;
      }
      const act = ref.slice(0, at).toLowerCase();
      const ver = ref.slice(at + 1);
      // versions に一致、または safe_tags があり「安全版タグでも SHA でもない」参照は汚染の可能性（trivy-action）
      const known = compromised.find((c) => c.action.toLowerCase() === act && (c.versions.includes(ver) || (!!c.safe_tags && !/^[0-9a-f]{40}$/.test(ver) && !c.safe_tags.includes(ver))));
      const org = compromised.some((c) => c.action.endsWith('/*') && act.startsWith(c.action.slice(0, -1).toLowerCase()));
      if (known) {
        uses.push({ ref: clip(ref), kind: 'compromised' });
        push(ctx, { level: 'CRITICAL', module: '§22', campaign: 'ghostaction-oct2026', path: f.relPath, code: 's22.poisoned_tag', params: { ref }, ruleId: `s22-pinning:${ref}`, evidenceSha: f.sha256, kind: 'gha.unpinned' });
      } else if (/^[0-9a-f]{40}$/.test(ver)) {
        uses.push({ ref: clip(ref), kind: 'sha' });
        if (org) push(ctx, { level: 'MEDIUM', module: '§22', campaign: 'ghostaction-oct2026', path: f.relPath, code: 's22.risky_publisher_sha', params: { action: act }, ruleId: `s22-pinning:${ref}`, evidenceSha: f.sha256 });
      } else {
        uses.push({ ref: clip(ref), kind: 'tag' });
        push(ctx, { level: org ? 'CRITICAL' : 'HIGH', module: '§22', campaign: 'ghostaction-oct2026', path: f.relPath, code: org ? 's22.risky_publisher_tag' : 's22.unpinned', params: { ref }, ruleId: `s22-pinning:${ref}`, evidenceSha: f.sha256, kind: 'gha.unpinned' });
      }
    }
    if (/(trivy-version|version):\s*["']?v?0\.69\.4["']?\s*$/m.test(y) && /trivy/.test(y)) {
      push(ctx, { level: 'CRITICAL', module: '§22', campaign: 'ghostaction-oct2026', path: f.relPath, code: 's22.trivy_version', ruleId: 's22-trivy-binary', evidenceSha: f.sha256 });
    }
    if (isWorkflow) ctx.viewers.actions.push({ path: f.relPath, uses, prTarget });
  }
}

interface Manifest { name?: unknown; update_url?: unknown; permissions?: unknown; optional_permissions?: unknown; host_permissions?: unknown; content_scripts?: unknown }

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

export function extensionRules(ctx: RuleCtx): void {
  ctx.checks.add('s24-update-url').add('s24-permissions').add('s42-known').add('s42-escalation');
  const be = ctx.ioc.browser_extensions;
  const manifests = readable(ctx).filter((x) => x.name === 'manifest.json' && (/(^|\/)Extensions\//.test(x.relPath) || /"manifest_version"\s*:/.test(x.text)));
  const parsed: { path: string; perms: string[] }[] = [];
  for (const f of manifests) {
    let m: Manifest;
    try { m = JSON.parse(f.text) as Manifest; } catch { continue; }
    const cs = Array.isArray(m.content_scripts) ? (m.content_scripts as { matches?: unknown }[]).flatMap((c) => strings(c.matches)) : [];
    const perms = [...strings(m.permissions), ...strings(m.optional_permissions), ...strings(m.host_permissions), ...cs];
    const dangerous = be.dangerous_permissions.filter((p) => perms.includes(p));
    const allUrls = perms.includes('<all_urls>');
    const uu = typeof m.update_url === 'string' ? m.update_url : '';
    const unofficial = uu !== '' && !be.official_update_urls.includes(uu);
    const name = typeof m.name === 'string' ? m.name : '';
    ctx.viewers.extensions.push({ path: f.relPath, name: clip(name, 60), dangerous, allUrls, unofficialUpdate: unofficial });
    parsed.push({ path: f.relPath, perms: [...dangerous, ...(allUrls ? ['<all_urls>'] : [])] });
    if (unofficial) push(ctx, { level: 'HIGH', module: '§24', campaign: null, path: f.relPath, code: 's24.update_url', ruleId: 's24-update-url', evidenceSha: f.sha256 });
    if (dangerous.length && allUrls) push(ctx, { level: 'HIGH', module: '§24', campaign: null, path: f.relPath, code: 's24.perms_all_urls', params: { permissions: dangerous.join(' ') }, ruleId: 's24-permissions', evidenceSha: f.sha256 });
    else if (dangerous.length) push(ctx, { level: 'MEDIUM', module: '§24', campaign: null, path: f.relPath, code: 's24.perms', params: { permissions: dangerous.join(' ') }, ruleId: 's24-permissions', evidenceSha: f.sha256 });
    else if (allUrls) push(ctx, { level: 'MEDIUM', module: '§24', campaign: null, path: f.relPath, code: 's24.all_urls', ruleId: 's24-permissions', evidenceSha: f.sha256 });
    if (name && be.known_campaigns.some((k) => k.name.includes(name))) {
      push(ctx, { level: 'HIGH', module: '§42', campaign: null, path: f.relPath, code: 's42.known_name', params: { name }, ruleId: 's42-known', evidenceSha: f.sha256 });
    }
  }
  // 同一拡張 ID の複数バージョン間で危険パーミッションが増えていないか（所有権移転型）
  const byId = new Map<string, { ver: string; path: string; perms: string[] }[]>();
  for (const p of parsed) {
    const m = /(^|\/)Extensions\/([^/]+)\/([^/]+)\/manifest\.json$/.exec(p.path);
    if (!m?.[2] || !m[3]) continue;
    const id = dirname(dirname(p.path));
    byId.set(id, [...(byId.get(id) ?? []), { ver: m[3], path: p.path, perms: p.perms }]);
  }
  for (const list of byId.values()) {
    list.sort((a, b) => a.ver.localeCompare(b.ver, 'en', { numeric: true }));
    for (let i = 1; i < list.length; i++) {
      const added = (list[i]?.perms ?? []).filter((x) => !(list[i - 1]?.perms ?? []).includes(x));
      if (added.length) push(ctx, { level: 'HIGH', module: '§42', campaign: null, path: list[i]?.path ?? null, code: 's42.perms_added', params: { permissions: added.join(' ') }, ruleId: 's42-escalation' });
    }
  }
}

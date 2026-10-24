// §21 / §22 / §38 GitHub Actions, §24 / §42 browser extensions
import { pathMatch, push, readable, type RuleCtx } from '../context';
import type { UsesRef } from '../types';
import { asciiLower, clip, dirname, lf } from '../util';

const lead = (x: string) => (/^[ \t]*/.exec(x)?.[0] ?? '').length;
/** Removes node properties (anchors &x, tags !!str / !tag) from the start (same as props in CLI yaml_flatten) */
const yamlProps = (v: string) => { let x = v; for (let m = /^(&[^ \t]+|![^ \t]*)([ \t]+|$)/.exec(x); m; m = /^(&[^ \t]+|![^ \t]*)([ \t]+|$)/.exec(x)) x = x.slice(m[0].length); return x; };
const yamlAlias = (v: string) => /^\*[^ \t,\]}]+[ \t]*(#.*)?$/.test(v);
/** Bracket depth outside quotes ([ { and ] }) */
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
/** Removes end-of-line comments outside quotes */
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
 * Stage 1 of YAML normalization (same as CLI yaml_flatten). Removes node properties (&anchor / !tag) and expands flow sequences ("steps: [ {uses: a}, … ]",
 * including multi-line ones) into block sequences with one element per line. Aliases (*x / <<: *x) are not resolved; a "#ZES-YAML-ALIAS" line is emitted.
 * The content of block scalars (run: | etc.) are passed through as is.
 */
// line-based like the CLI's grep (lf: lines end at LF only)
const SECRETS_EXPR = lf(/\$\{\{([^}\n]*[^A-Za-z0-9_.\n])?secrets([\][.\t\v\f\r )]|$)/im);
const WRITE_ALL = lf(/^[\t\v\f\r ]*permissions:[\t\v\f\r ]*write-all/m);
const TRIVY_0694 = lf(/(trivy-version|version):[\t\v\f\r ]*["']?v?0\.69\.4["']?[\t\v\f\r ]*$/m);

export function yamlFlatten(yaml: string): string[] {
  const src = yaml.split('\n').map((l) => l.replace(/\r$/, ''));
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

/** Whether it contains an alias (*x) (the CLI records yaml_alias_unresolved in errors[]) */
export const yamlHasAlias = (yaml: string) => yamlFlatten(yaml).includes('#ZES-YAML-ALIAS');

/**
 * Normalization of the workflow body (same as CLI workflow_text). After yamlFlatten, folds keys whose value continues on later lines into one line.
 *   - block scalars ("key: >-" / "key: |" etc.): join all following lines with deeper indentation, separated by spaces
 *   - when a plain scalar follows a key with an empty value (the value on the line after "- uses:"): join the following lines that are
 *     deeper and not a mapping/sequence (multi-line folding of YAML plain scalars)
 * A "uses: …" written inside run: | becomes part of the run: value through this folding and is not counted as a step.
 */
export function workflowText(yaml: string): string[] {
  const src = yamlFlatten(yaml);
  const out: string[] = [];
  let pend = '';
  let pind = 0;
  let blk = false;
  let acc = '';
  const KEY_ONLY = /^[\t\v\f\r ]*(-[\t\v\f\r ]+)?["']?[A-Za-z0-9_.$-]+["']?:[\t\v\f\r ]*([>|][-+0-9]*)?[\t\v\f\r ]*(#.*)?$/;
  const NODE = /^[\t\v\f\r ]*(-([\t\v\f\r ]|$)|["']?[A-Za-z0-9_.$-]+["']?:([\t\v\f\r ]|$))/;
  for (const line of src) {
    if (pend !== '') {
      if (/^[\t\v\f\r ]*$/.test(line) || (!blk && /^[\t\v\f\r ]*#/.test(line))) continue;
      const lead = (/^[\t\v\f\r ]*/.exec(line)?.[0] ?? '').length;
      if (lead > pind && (blk || !NODE.test(line))) {
        let v = line.replace(/^[\t\v\f\r ]+/, '');
        if (!blk) v = v.replace(/[\t\v\f\r ]+#.*$/, '');
        v = v.replace(/[\t\v\f\r ]+$/, '');
        acc += (acc === '' ? '' : ' ') + v;
        continue;
      }
      out.push(pend + (acc !== '' ? ' ' + acc : ''));
      pend = ''; acc = '';
    }
    if (KEY_ONLY.test(line)) {
      pind = (/^[\t\v\f\r ]*/.exec(line)?.[0] ?? '').length;
      if (/^[\t\v\f\r ]*-[\t\v\f\r ]/.test(line)) pind = line.length - line.replace(/^[\t\v\f\r ]*-[\t\v\f\r ]+/, '').length - 1;
      pend = line.replace(/[\t\v\f\r ]*(#.*)?$/, '');
      blk = /:[\t\v\f\r ]*[>|][-+0-9]*$/.test(pend);
      pend = pend.replace(/[\t\v\f\r ]*[>|][-+0-9]*$/, '');
      acc = '';
      continue;
    }
    out.push(line);
  }
  if (pend !== '') out.push(pend + (acc !== '' ? ' ' + acc : ''));
  return out;
}

/** ref kind per actions/checkout step (same evaluation as CLI §21; input is the lines normalized by workflowText). */
export function checkoutRefs(yaml: string): ('noref' | 'prhead' | 'otherref' | 'exprref')[] {
  const out: ('noref' | 'prhead' | 'otherref' | 'exprref')[] = [];
  let inChk = false;
  let ind = 0;
  let ref: 'prhead' | 'otherref' | 'exprref' | '' = '';
  const flush = () => { if (inChk) out.push(ref === '' ? 'noref' : ref); inChk = false; ref = ''; };
  // ref is looked up both in block mappings (ref: at line start) and flow mappings ({ ref: … } / , ref: …)
  const getRef = (s: string) => {
    const m = /^[\t\v\f\r ]*ref:/.exec(s) ?? /[{,][\t\v\f\r ]*ref:/.exec(s);
    if (!m) return;
    let r = s.slice(m.index + m[0].length).replace(/^[\t\v\f\r ]*/, '');
    if (/^["']/.test(r)) {
      const q = r[0]!;
      r = r.slice(1);
      const k = r.indexOf(q);
      if (k >= 0) r = r.slice(0, k);
    } else {
      r = r.replace(/[,}].*$/, '');
    }
    // Normalization: to lower case, remove spaces, convert subscript notation (github.event['pull_request']['head'] / ["…"]) to dot notation
    r = asciiLower(r).replace(/[ \t]/g, '').replace(/\[["']/g, '.').replace(/["']\]/g, '');
    if (/github\.(event\.pull_request\.(head|merge_commit_sha|number)|head_ref|event\.number)|refs\/pull\//.test(r)) ref = 'prhead';
    // If only base-side expressions (base.sha / base.ref / base_ref / github.sha / github.ref / default_branch), it does not come from the PR
    else if (r.replace(/\$\{\{(github\.event\.pull_request\.base\.(sha|ref)|github\.base_ref|github\.sha|github\.ref|github\.event\.repository\.default_branch)\}\}/g, '').includes('${{')) ref = 'exprref'; // any other expression cannot be confirmed as not coming from the PR (at least HIGH)
    else ref = 'otherref';
  };
  for (const line of workflowText(yaml)) {
    const lead = (/^[\t\v\f\r ]*/.exec(line)?.[0] ?? '').length;
    // Quoted ones (uses: "actions/checkout@v4"), owner names differing in case, and flow-mapping steps are covered too
    if (/^[\t\v\f\r ]*(-[\t\v\f\r ]+)?(\{([^}#]*,)?[\t\v\f\r ]*)?uses:[\t\v\f\r ]*["']?actions\/checkout@/.test(asciiLower(line))) {
      flush(); inChk = true; ind = lead;
      const at = line.lastIndexOf('actions/checkout@');
      getRef(at < 0 ? line : line.slice(at + 'actions/checkout@'.length));
      continue;
    }
    if (!inChk) continue;
    if (/^[\t\v\f\r ]*-[\t\v\f\r ]/.test(line) && lead <= ind) { flush(); continue; }
    getRef(line);
  }
  flush();
  return out;
}

/** uses: references for §22 (as in the CLI, only the uses: of a step/flow mapping at the start of each normalized line; duplicates removed). */
export function usesRefs(yaml: string): string[] {
  const seen = new Set<string>();
  for (const line of workflowText(yaml)) {
    const m = /^[\t\v\f\r -]*(\{([^}#]*,)?[\t\v\f\r ]*)?uses:[\t\v\f\r ]*["']?[^"'\t\n\v\f\r #,}]+/.exec(line);
    if (!m) continue;
    seen.add(m[0].replace(/.*uses:[\t\v\f\r ]*["']?/, ''));
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
    // Expression context names are case-insensitive (${{ SECRETS.X }} / ${{ toJSON(secrets) }} / secrets['X'] are also secrets references)
    if (isWorkflow && prTarget && /actions\/checkout@/i.test(y) && SECRETS_EXPR.test(y)) {
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
    if (WRITE_ALL.test(y)) {
      push(ctx, { level: 'HIGH', module: '§21', campaign: 'ghostaction-oct2026', path: f.relPath, code: 's21.write_all', ruleId: 's21-writeall', evidenceSha: f.sha256 });
    }
    if (isWorkflow && yamlHasAlias(y)) ctx.errors.push({ module: '§21', reason: `yaml_alias_unresolved:${f.relPath}` });
    const n = new Set([...y.matchAll(/secrets\.([A-Za-z0-9_]+)/gi)].map((m) => asciiLower(m[1]!))).size;
    if (n > threshold) push(ctx, { level: 'HIGH', module: '§38', campaign: 'ghostaction-oct2026', path: f.relPath, code: 's38.many_secrets', params: { n, threshold }, ruleId: 's38-secrets', evidenceSha: f.sha256 });
    if (/tojson\([\t\v\f\r ]*secrets[\t\v\f\r ]*(\.[\t\v\f\r ]*\*[\t\v\f\r ]*)?\)/i.test(y)) push(ctx, { level: 'CRITICAL', module: '§38', campaign: 'ghostaction-oct2026', path: f.relPath, code: 's38.tojson_secrets', ruleId: 's38-tojson', evidenceSha: f.sha256 });

    const uses: UsesRef[] = [];
    // uses: on each normalized line (including flow mappings, values on the next line and block scalars; strings inside run: are not counted)
    for (const ref of usesRefs(y)) {
      if (ref.startsWith('./') || ref.startsWith('docker://')) { uses.push({ ref: clip(ref), kind: 'local' }); continue; }
      const at = ref.lastIndexOf('@');
      if (at < 0) {
        uses.push({ ref: clip(ref), kind: 'tag' });
        push(ctx, { level: 'HIGH', module: '§22', campaign: 'ghostaction-oct2026', path: f.relPath, code: 's22.no_version', params: { ref }, ruleId: `s22-pinning:${ref}`, evidenceSha: f.sha256, kind: 'gha.unpinned' });
        continue;
      }
      const act = asciiLower(ref.slice(0, at));
      const ver = ref.slice(at + 1);
      // A reference that matches versions, or, when safe_tags exists, is "neither a safe tag nor a SHA", is possibly poisoned (trivy-action)
      const known = compromised.find((c) => asciiLower(c.action) === act && (c.versions.includes(ver) || (!!c.safe_tags && !/^[0-9a-f]{40}$/.test(ver) && !c.safe_tags.includes(ver))));
      const org = compromised.some((c) => c.action.endsWith('/*') && act.startsWith(asciiLower(c.action.slice(0, -1))));
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
    if (TRIVY_0694.test(y) && /trivy/.test(y)) {
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
  // a manifest.json under Extensions/, or one whose parsed document has manifest_version (decoded keys, not the raw text)
  const manifests = readable(ctx).filter((x) => x.name === 'manifest.json');
  const parsed: { path: string; perms: string[] }[] = [];
  for (const f of manifests) {
    let m: Manifest;
    try { m = JSON.parse(f.text) as Manifest; } catch { continue; }
    if (!/(^|\/)Extensions\//.test(f.relPath) && !(m && typeof m === 'object' && !Array.isArray(m) && Object.prototype.hasOwnProperty.call(m, 'manifest_version'))) continue;
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
  // Whether dangerous permissions increased between several versions of the same extension ID (ownership-transfer type)
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

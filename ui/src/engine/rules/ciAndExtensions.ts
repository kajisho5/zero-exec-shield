// §21 / §22 / §38 GitHub Actions、§24 / §42 ブラウザ拡張
import { pathMatch, push, readable, type RuleCtx } from '../context';
import type { UsesRef } from '../types';
import { clip, dirname } from '../util';

/**
 * ワークフロー本文の正規化（CLI workflow_text と同じ）。CRLF・BOM を除き、値が次行以降に続くキーを 1 行に畳む。
 *   - ブロックスカラー（"key: >-" / "key: |" 等）: より深くインデントされた後続行を全て空白区切りで連結
 *   - 値が空のキーの後にプレーンスカラーが続く場合（"- uses:" の次行に値）: マッピング/シーケンスでない
 *     より深い後続行を連結（YAML のプレーンスカラーの複数行折り返し）
 * run: | の中に書かれた "uses: …" はこの畳み込みで run: の値の一部になり、ステップとして数えない。
 */
export function workflowText(yaml: string): string[] {
  const src = yaml.replace(/^﻿/, '').split('\n').map((l) => l.replace(/\r$/, ''));
  if (src.length && src[src.length - 1] === '') src.pop();
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
export function checkoutRefs(yaml: string): ('noref' | 'prhead' | 'otherref')[] {
  const out: ('noref' | 'prhead' | 'otherref')[] = [];
  let inChk = false;
  let ind = 0;
  let ref: 'prhead' | 'otherref' | '' = '';
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
    ref = /github\.(event\.pull_request\.head|head_ref)/.test(r) ? 'prhead' : 'otherref';
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
  for (const f of pathMatch(ctx, /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$|(^|\/)action\.ya?ml$/)) {
    const y = f.text;
    const isWorkflow = /\.github\/workflows\//.test(f.relPath);
    const prTarget = /(^|[^A-Za-z0-9_])pull_request_target([^A-Za-z0-9_]|$)/.test(y);
    if (isWorkflow && prTarget && /actions\/checkout@/i.test(y) && /\$\{\{\s*secrets\./.test(y)) {
      const refs = checkoutRefs(y);
      if (refs.includes('prhead')) {
        push(ctx, { level: 'CRITICAL', module: '§21', campaign: 'ghostaction-oct2026', path: f.relPath, detail: 'pull_request_target + PR head の checkout + secrets 参照（pwn request）', ruleId: 's21-prtarget:prhead', evidenceSha: f.sha256 });
      }
      if (refs.includes('noref')) {
        push(ctx, { level: 'HIGH', module: '§21', campaign: 'ghostaction-oct2026', path: f.relPath, detail: 'pull_request_target + actions/checkout(refなし) + secrets 参照', ruleId: 's21-prtarget:noref', evidenceSha: f.sha256 });
      }
    }
    if (/key:.*github\.event\.pull_request\.number/.test(y)) {
      push(ctx, { level: 'HIGH', module: '§21', campaign: 'ghostaction-oct2026', path: f.relPath, detail: 'actions/cache のキーに PR 番号（キャッシュポイズニング）', ruleId: 's21-cache', evidenceSha: f.sha256 });
    }
    if (/^\s*permissions:\s*write-all/m.test(y)) {
      push(ctx, { level: 'HIGH', module: '§21', campaign: 'ghostaction-oct2026', path: f.relPath, detail: 'permissions: write-all', ruleId: 's21-writeall', evidenceSha: f.sha256 });
    }
    const n = new Set([...y.matchAll(/secrets\.([A-Za-z0-9_]+)/g)].map((m) => m[1])).size;
    if (n > 10) push(ctx, { level: 'HIGH', module: '§38', campaign: 'ghostaction-oct2026', path: f.relPath, detail: `ワークフローが ${n} 種類の secrets.* を参照（一括収集の疑い）`, ruleId: 's38-secrets', evidenceSha: f.sha256 });
    if (/toJSON\(\s*secrets\s*\)/.test(y)) push(ctx, { level: 'CRITICAL', module: '§38', campaign: 'ghostaction-oct2026', path: f.relPath, detail: 'toJSON(secrets) で全シークレットを展開', ruleId: 's38-tojson', evidenceSha: f.sha256 });

    const uses: UsesRef[] = [];
    // 正規化後の各行の uses:（フローマッピング・次行の値・ブロックスカラーを含む。run: の中の文字列は数えない）
    for (const ref of usesRefs(y)) {
      if (ref.startsWith('./') || ref.startsWith('docker://')) { uses.push({ ref: clip(ref), kind: 'local' }); continue; }
      const at = ref.lastIndexOf('@');
      if (at < 0) {
        uses.push({ ref: clip(ref), kind: 'tag' });
        push(ctx, { level: 'HIGH', module: '§22', campaign: 'ghostaction-oct2026', path: f.relPath, detail: `uses: ${clip(ref, 80)} がバージョン未指定`, ruleId: `s22-pinning:${ref}`, evidenceSha: f.sha256 });
        continue;
      }
      const act = ref.slice(0, at).toLowerCase();
      const ver = ref.slice(at + 1);
      // versions に一致、または safe_tags があり「安全版タグでも SHA でもない」参照は汚染の可能性（trivy-action）
      const known = compromised.find((c) => c.action.toLowerCase() === act && (c.versions.includes(ver) || (!!c.safe_tags && !/^[0-9a-f]{40}$/.test(ver) && !c.safe_tags.includes(ver))));
      const org = compromised.some((c) => c.action.endsWith('/*') && act.startsWith(c.action.slice(0, -1).toLowerCase()));
      if (known) {
        uses.push({ ref: clip(ref), kind: 'compromised' });
        push(ctx, { level: 'CRITICAL', module: '§22', campaign: 'ghostaction-oct2026', path: f.relPath, detail: `汚染されたタグ参照の可能性（${clip(ref, 80)}）。安全版タグまたは検証済み SHA に固定`, ruleId: `s22-pinning:${ref}`, evidenceSha: f.sha256 });
      } else if (/^[0-9a-f]{40}$/.test(ver)) {
        uses.push({ ref: clip(ref), kind: 'sha' });
        if (org) push(ctx, { level: 'MEDIUM', module: '§22', campaign: 'ghostaction-oct2026', path: f.relPath, detail: `侵害履歴のある発行元のアクション ${clip(act, 80)}（SHA 固定済み）`, ruleId: `s22-pinning:${ref}`, evidenceSha: f.sha256 });
      } else {
        uses.push({ ref: clip(ref), kind: 'tag' });
        push(ctx, { level: org ? 'CRITICAL' : 'HIGH', module: '§22', campaign: 'ghostaction-oct2026', path: f.relPath, detail: org ? `侵害履歴のある発行元のアクションをタグ参照（${clip(ref, 80)}）` : `SHA 固定されていないアクション参照（${clip(ref, 80)}）`, ruleId: `s22-pinning:${ref}`, evidenceSha: f.sha256 });
      }
    }
    if (/(trivy-version|version):\s*["']?v?0\.69\.4["']?\s*$/m.test(y) && /trivy/.test(y)) {
      push(ctx, { level: 'CRITICAL', module: '§22', campaign: 'ghostaction-oct2026', path: f.relPath, detail: 'Trivy 本体の悪性版 v0.69.4 を指定（安全版は v0.69.3）', ruleId: 's22-trivy-binary', evidenceSha: f.sha256 });
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
    if (unofficial) push(ctx, { level: 'HIGH', module: '§24', campaign: null, path: f.relPath, detail: '拡張の update_url が公式ストア以外', ruleId: 's24-update-url', evidenceSha: f.sha256 });
    if (dangerous.length && allUrls) push(ctx, { level: 'HIGH', module: '§24', campaign: null, path: f.relPath, detail: `危険パーミッション（${dangerous.join(' ')}）+ <all_urls>`, ruleId: 's24-permissions', evidenceSha: f.sha256 });
    else if (dangerous.length) push(ctx, { level: 'MEDIUM', module: '§24', campaign: null, path: f.relPath, detail: `危険パーミッション（${dangerous.join(' ')}）`, ruleId: 's24-permissions', evidenceSha: f.sha256 });
    else if (allUrls) push(ctx, { level: 'MEDIUM', module: '§24', campaign: null, path: f.relPath, detail: '全サイトへのアクセス（<all_urls>）', ruleId: 's24-permissions', evidenceSha: f.sha256 });
    if (name && be.known_campaigns.some((k) => k.name.includes(name))) {
      push(ctx, { level: 'HIGH', module: '§42', campaign: null, path: f.relPath, detail: '既知の悪性/侵害拡張と同名', ruleId: 's42-known', evidenceSha: f.sha256 });
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
      if (added.length) push(ctx, { level: 'HIGH', module: '§42', campaign: null, path: list[i]?.path ?? null, detail: `拡張の更新で危険パーミッションが追加（${added.join(' ')}）。所有権移転型の悪性アップデート疑い`, ruleId: 's42-escalation' });
    }
  }
}

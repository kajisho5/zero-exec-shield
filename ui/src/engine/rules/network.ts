// §18 Network IoCs (file content, pasted text)
import { push, readable, type RuleCtx } from '../context';
import type { IocDb } from '../ioc';
import { asciiLower, refang, type FCode } from '../util';

/** malicious = attacker infrastructure (CRITICAL) / legit = legitimate infrastructure abused in an attack (MEDIUM; beware of false positives) */
export interface NetIoc { value: string; campaign: string; kind: 'malicious' | 'legit' }

export function networkIocs(ioc: IocDb): NetIoc[] {
  const w = ioc.worm_iocs;
  const m = (xs: string[] | undefined, campaign: string, kind: NetIoc['kind']) => (xs ?? []).map((v) => ({ value: refang(v), campaign, kind }));
  const all: NetIoc[] = [
    ...m(w.chaindrop.domains, 'chaindrop-keyv', 'malicious'),
    ...m(w.chaindrop.eth_contracts, 'chaindrop-keyv', 'malicious'),
    ...m(w.teampcp.c2_ip, 'teampcp-mini-shai-hulud', 'malicious'),
    ...m(w.teampcp.c2_domains, 'teampcp-mini-shai-hulud', 'malicious'),
    ...m(w.chaindrop.legit_infra, 'chaindrop-keyv', 'legit'),
    ...m(w.teampcp.legit_infra, 'teampcp-mini-shai-hulud', 'legit'),
    ...(ioc.intel?.network ?? []).flatMap((n) => [
      ...m([...(n.domains ?? []), ...(n.ips ?? []), ...(n.urls ?? [])], n.campaign, 'malicious'),
      ...m(n.legit_infra, n.campaign, 'legit'),
    ]),
  ];
  // When the same value is listed in several campaigns, the first one (campaign-specific worm_iocs take precedence)
  const seen = new Set<string>();
  return all.filter((i) => { const k = asciiLower(i.value); return seen.has(k) ? false : (seen.add(k), true); });
}

/** The last n commands of a shell history. zsh extended history (": <start time>:<elapsed seconds>;<command>") merges multi-line entries into one and strips the prefix. */
export function lastHistoryEntries(text: string, n: number): string[] {
  const lines = text.split(/\r?\n/);
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  const ext = /^: \d+:\d+;/;
  const zsh = lines.some((x) => ext.test(x));
  const entries: string[] = [];
  for (const l of lines) {
    if (zsh && entries.length && !ext.test(l) && /\\$/.test(entries[entries.length - 1] ?? '')) entries[entries.length - 1] += '\n' + l;
    else entries.push(l.replace(ext, ''));
  }
  return entries.slice(-n);
}

const HISTORY = /(^|\/)\.(bash|zsh)_history$/;

/** The CLI's s18 params (grep -o -i -F | sort -u | head -n3): the matched strings, leftmost-longest and not overlapping,
 *  in lower case, unique, C-locale order, the first 3 joined by spaces; the campaign of the first IoC entry that contains
 *  the first of them. */
function matched(low: string, hits: (NetIoc & { low: string })[], all: (NetIoc & { low: string })[]): { iocs: string; campaign: string | null } | null {
  if (!hits.length) return null;
  const occ: [number, number][] = [];
  for (const v of new Set(hits.map((h) => h.low))) for (let i = low.indexOf(v); i >= 0; i = low.indexOf(v, i + 1)) occ.push([i, v.length]);
  occ.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
  const found = new Set<string>();
  let end = 0;
  for (const [s, n] of occ) { if (s < end) continue; found.add(low.slice(s, s + n)); end = s + n; }
  const vals = [...found].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)).slice(0, 3);
  const first = vals[0]!;
  return { iocs: vals.join(' '), campaign: all.find((i) => i.low.includes(first))?.campaign ?? hits[0]?.campaign ?? null };
}

export function networkRules(ctx: RuleCtx): void {
  ctx.checks.add('s18-netioc').add('s18-history-curlsh');
  // CLI check_s18: execution in curl|sh form among the last 5 shell history entries
  for (const f of readable(ctx).filter((x) => HISTORY.test(x.relPath))) {
    if (lastHistoryEntries(f.text, 5).some((e) => /(curl|wget)[^|]*\|[\t\v\f\r ]*(ba|z)?sh/.test(e))) {
      push(ctx, { level: 'HIGH', module: '§18', campaign: null, path: f.relPath, code: 's18.history_curl_sh', ruleId: 's18-history-curlsh', evidenceSha: f.sha256 });
    }
  }
  // the IoC values lower-cased once (asciiLower per IoC per file was most of the time of a 10 000-file scan)
  const iocs = networkIocs(ctx.ioc).map((i) => ({ ...i, low: asciiLower(i.value) }));
  // §34 hosts file (the part of CLI check_s34 that can be evaluated from files): overrides of registries/GitHub and C2 domains. Case-insensitive
  ctx.checks.add('s34-hosts');
  const esc = (x: string) => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  for (const f of readable(ctx).filter((x) => x.name === 'hosts')) {
    const body = f.text.split(/\r?\n/).filter((l) => !/^[\t\v\f\r ]*#/.test(l)).join('\n');
    for (const h of ctx.ioc.protected_hosts ?? []) {
      if (new RegExp(`[ \\t]${esc(h)}([ \\t]|$)`, 'im').test(body)) push(ctx, { level: 'HIGH', module: '§34', campaign: null, path: f.relPath, code: 's34.hosts_override', params: { host: h }, ruleId: `s34-hosts:${h}`, evidenceSha: f.sha256 });
    }
    const low = asciiLower(body);
    for (const i of iocs.filter((x) => x.kind === 'malicious' && !/^[0-9.]+$/.test(x.value))) {
      if (low.includes(i.low)) push(ctx, { level: 'CRITICAL', module: '§34', campaign: null, path: f.relPath, code: 's34.hosts_c2', params: { host: i.value }, ruleId: `s34-hosts-c2:${i.value}`, evidenceSha: f.sha256 });
    }
  }
  for (const f of readable(ctx)) {
    const low = asciiLower(f.text);
    const hits = iocs.filter((i) => low.includes(i.low));
    // CLI check_s18: shell history is not a network IoC file; a C2 domain / IP in it is s18.history_c2 (no campaign)
    if (HISTORY.test(f.relPath)) {
      if (hits.some((h) => h.kind === 'malicious')) push(ctx, { level: 'CRITICAL', module: '§18', campaign: null, path: f.relPath, code: 's18.history_c2', ruleId: 's18-netioc', evidenceSha: f.sha256 });
      continue;
    }
    const bad = matched(low, hits.filter((h) => h.kind === 'malicious'), iocs);
    const legit = matched(low, hits.filter((h) => h.kind === 'legit'), iocs);
    if (bad) push(ctx, { level: 'CRITICAL', module: '§18', campaign: bad.campaign, path: f.relPath, code: 's18.network_ioc', params: { iocs: bad.iocs }, ruleId: 's18-netioc', evidenceSha: f.sha256 });
    if (legit) push(ctx, { level: 'MEDIUM', module: '§18', campaign: legit.campaign, path: f.relPath, code: 's18.legit_infra', params: { iocs: legit.iocs }, ruleId: 's18-netioc-legit', evidenceSha: f.sha256 });
  }
}

/** Rule definitions for paste evaluation. Only rules and counts are displayed (the pasted content is never redisplayed). */
export const PASTE_RULES: { id: string; code: FCode; re: RegExp }[] = [
  { id: 'paste-base64', code: 'paste.base64', re: /[A-Za-z0-9+/]{40,}={0,2}|base64[\t\v\f\r ]+(-d|--decode)/g },
  { id: 'paste-exec', code: 'paste.exec', re: /\b(exec|eval)[\t\v\f\r ]*\(/g },
  { id: 'paste-curl', code: 'paste.curl', re: /\b(curl|wget)\b/g },
  { id: 'paste-pipe-shell', code: 'paste.pipe_shell', re: /\|[\t\v\f\r ]*(ba|z)?sh\b/g },
];

export interface PasteHit { ruleId: string; code: FCode; params: Record<string, string | number>; level: 'CRITICAL' | 'HIGH' | 'MEDIUM'; campaign: string | null }

export function analyzePasteText(text: string, ioc: IocDb): PasteHit[] {
  const low = asciiLower(text);
  const out: PasteHit[] = [];
  // One finding per kind and campaign with the total count (the matched values are not shown: they are part of the text)
  const byCampaign = new Map<string, PasteHit>();
  for (const i of networkIocs(ioc)) {
    const v = asciiLower(i.value);
    let n = 0;
    for (let p = low.indexOf(v); p >= 0; p = low.indexOf(v, p + v.length)) n++;
    if (!n) continue;
    const k = `${i.kind}\0${i.campaign}`;
    const prev = byCampaign.get(k);
    if (prev) { prev.params['count'] = Number(prev.params['count']) + n; continue; }
    const hit: PasteHit = i.kind === 'malicious'
      ? { ruleId: `paste-ioc:${i.campaign}`, code: 'paste.ioc', params: { count: n }, level: 'CRITICAL', campaign: i.campaign }
      : { ruleId: `paste-legit:${i.campaign}`, code: 'paste.legit', params: { count: n }, level: 'MEDIUM', campaign: i.campaign };
    byCampaign.set(k, hit);
    out.push(hit);
  }
  for (const r of PASTE_RULES) {
    const n = [...text.matchAll(r.re)].length;
    if (n) out.push({ ruleId: r.id, code: r.code, params: { count: n }, level: 'HIGH', campaign: null });
  }
  return out;
}

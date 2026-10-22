// §18 ネットワーク IoC（ファイル内容・貼り付けテキスト）
import { push, readable, type RuleCtx } from '../context';
import type { IocDb } from '../ioc';
import { refang } from '../util';

/** malicious = 攻撃者のインフラ（CRITICAL）/ legit = 攻撃に悪用された正規インフラ（MEDIUM、誤検知に注意） */
export interface NetIoc { value: string; campaign: string; kind: 'malicious' | 'legit' }

export function networkIocs(ioc: IocDb): NetIoc[] {
  const w = ioc.worm_iocs;
  const m = (xs: string[] | undefined, campaign: string, kind: NetIoc['kind']) => (xs ?? []).map((v) => ({ value: refang(v), campaign, kind }));
  return [
    ...m(w.chaindrop.domains, 'chaindrop-keyv', 'malicious'),
    ...m(w.chaindrop.eth_contracts, 'chaindrop-keyv', 'malicious'),
    ...m(w.teampcp.c2_ip, 'teampcp-mini-shai-hulud', 'malicious'),
    ...m(w.teampcp.c2_domains, 'teampcp-mini-shai-hulud', 'malicious'),
    ...m(w.chaindrop.legit_infra, 'chaindrop-keyv', 'legit'),
    ...m(w.teampcp.legit_infra, 'teampcp-mini-shai-hulud', 'legit'),
  ];
}

export function networkRules(ctx: RuleCtx): void {
  ctx.checks.add('s18-netioc');
  const iocs = networkIocs(ctx.ioc);
  for (const f of readable(ctx)) {
    const low = f.text.toLowerCase();
    const hits = iocs.filter((i) => low.includes(i.value.toLowerCase()));
    const bad = hits.filter((h) => h.kind === 'malicious');
    const legit = hits.filter((h) => h.kind === 'legit');
    if (bad.length) push(ctx, { level: 'CRITICAL', module: '§18', campaign: bad[0]?.campaign ?? null, path: f.relPath, detail: `ネットワーク IoC を含むファイル（${bad.length} 件一致）`, ruleId: 's18-netioc', evidenceSha: f.sha256 });
    if (legit.length) push(ctx, { level: 'MEDIUM', module: '§18', campaign: legit[0]?.campaign ?? null, path: f.relPath, detail: `攻撃に悪用された正規インフラへの参照（${legit.length} 件）。正規利用か、想定外の接続元かを確認`, ruleId: 's18-netioc-legit', evidenceSha: f.sha256 });
  }
}

/** 貼り付け判定のルール定義。表示はルール ID と件数のみ（貼り付け内容を再表示しない）。 */
export const PASTE_RULES: { id: string; title: string; re: RegExp }[] = [
  { id: 'paste-base64', title: 'Base64 文字列（40 文字以上）または base64 -d', re: /[A-Za-z0-9+/]{40,}={0,2}|base64\s+(-d|--decode)/g },
  { id: 'paste-exec', title: 'exec / eval の呼び出し', re: /\b(exec|eval)\s*\(/g },
  { id: 'paste-curl', title: 'curl / wget', re: /\b(curl|wget)\b/g },
  { id: 'paste-pipe-shell', title: '| bash / | sh（パイプ実行）', re: /\|\s*(ba|z)?sh\b/g },
];

export interface PasteHit { ruleId: string; title: string; count: number; level: 'CRITICAL' | 'HIGH' | 'MEDIUM'; campaign: string | null }

export function analyzePasteText(text: string, ioc: IocDb): PasteHit[] {
  const low = text.toLowerCase();
  const out: PasteHit[] = [];
  for (const i of networkIocs(ioc)) {
    const v = i.value.toLowerCase();
    let n = 0;
    for (let p = low.indexOf(v); p >= 0; p = low.indexOf(v, p + v.length)) n++;
    if (n) {
      out.push(i.kind === 'malicious'
        ? { ruleId: `paste-ioc:${i.value}`, title: 'C2 ドメイン / IP（ネットワーク IoC）', count: n, level: 'CRITICAL', campaign: i.campaign }
        : { ruleId: `paste-legit:${i.value}`, title: '攻撃に悪用された正規インフラ（要確認）', count: n, level: 'MEDIUM', campaign: i.campaign });
    }
  }
  for (const r of PASTE_RULES) {
    const n = [...text.matchAll(r.re)].length;
    if (n) out.push({ ruleId: r.id, title: r.title, count: n, level: 'HIGH', campaign: null });
  }
  return out;
}

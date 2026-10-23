import type { RuleCtx } from './context';
import { IOC, type IocDb } from './ioc';
import { aiAssistantRules, mcpRegistryRules, mcpRules } from './rules/agentConfig';
import { actionsRules, extensionRules } from './rules/ciAndExtensions';
import { emudhraRules, infraRules, intelRules } from './rules/intel';
import { buildHookRules, containerRules, credentialRules, homeRules, ebpfRules, modelSupplyRules, persistenceRules, sigstoreRules } from './rules/codeAndHost';
import { analyzePasteText } from './rules/network';
import { phpRules } from './rules/php';
import { networkRules } from './rules/network';
import { blastRadius, filenameRules, packageRules, pthRules } from './rules/supplyChain';
import { skillpactRules } from './skillpact';
import type { EngineResult, FileInput, Finding } from './types';
import { SEVERITY_RANK } from './types';
import { makeFinding } from './util';

export * from './types';
export { IOC } from './ioc';

function sortFindings(xs: Finding[]): Finding[] {
  return xs.sort((a, b) => SEVERITY_RANK[b.level] - SEVERITY_RANK[a.level] || Number(a.module.slice(1)) - Number(b.module.slice(1)) || (a.path ?? '').localeCompare(b.path ?? ''));
}

/** 投入ファイルを判定する。戻り値にファイル内容は含まれない（パス・ルール ID・固定文言・ハッシュのみ）。 */
export async function analyzeFiles(input: FileInput[], ioc: IocDb = IOC): Promise<EngineResult> {
  const seen = new Set<string>();
  const files = input.filter((f) => (seen.has(f.relPath) ? false : (seen.add(f.relPath), true)));
  const first = files[0]?.relPath ?? '';
  const top = first.includes('/') ? first.slice(0, first.indexOf('/')) : '';
  const root = top && files.every((f) => f.relPath.startsWith(top + '/')) ? top : '';
  const ctx: RuleCtx = {
    files, byPath: new Map(files.map((f) => [f.relPath, f])), ioc, specs: [], blast: [],
    viewers: { mcp: [], actions: [], extensions: [] }, errors: [], checks: new Set(), root,
  };
  filenameRules(ctx);
  packageRules(ctx);
  pthRules(ctx);
  mcpRules(ctx);
  mcpRegistryRules(ctx);
  aiAssistantRules(ctx);
  networkRules(ctx);
  actionsRules(ctx);
  extensionRules(ctx);
  containerRules(ctx);
  buildHookRules(ctx);
  modelSupplyRules(ctx);
  persistenceRules(ctx);
  homeRules(ctx);
  ebpfRules(ctx);
  sigstoreRules(ctx);
  credentialRules(ctx);
  infraRules(ctx);
  phpRules(ctx);
  emudhraRules(ctx);
  intelRules(ctx);
  blastRadius(ctx);
  const skillpact = skillpactRules(ctx);

  const findings: Finding[] = [];
  const ids = new Set<string>();
  for (const s of ctx.specs) {
    const f = await makeFinding(s);
    if (ids.has(f.id)) continue;
    ids.add(f.id);
    findings.push(f);
  }
  const stats = {
    files: files.length,
    read: files.filter((f) => f.readState === 'read').length,
    skippedSize: files.filter((f) => f.readState === 'skipped-size').length,
    skippedBinary: files.filter((f) => f.readState === 'skipped-binary').length,
    errors: files.filter((f) => f.readState === 'error').length,
    zeroByteDecoys: findings.filter((f) => f.ruleId === 's17-symjack').length,
  };
  if (stats.skippedSize) ctx.errors.push({ module: 'core', reason: `ui:skipped_size:${stats.skippedSize}` });
  if (stats.errors) ctx.errors.push({ module: 'core', reason: `ui:read_error:${stats.errors}` });
  return { findings: sortFindings(findings), skillpact, blastRadius: ctx.blast.sort((a, b) => a.path.localeCompare(b.path)), viewers: ctx.viewers, errors: ctx.errors, stats, checksRun: [...ctx.checks].sort() };
}

/** 貼り付けテキストの判定。内容は返さず、ルールと件数だけを Finding にする。 */
export async function analyzePaste(text: string, ioc: IocDb = IOC): Promise<Finding[]> {
  const hits = analyzePasteText(text, ioc);
  const out: Finding[] = [];
  for (const h of hits) {
    out.push(await makeFinding({ level: h.level, module: '§18', campaign: h.campaign, path: null, detail: `貼り付けテキスト: ${h.title}（${h.count} 件）`, ruleId: h.ruleId }));
  }
  return sortFindings(out);
}

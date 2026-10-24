import { homeLike, type RuleCtx } from './context';
import { gitDiscover } from './git';
import { IOC, type IocDb } from './ioc';
import { aiAssistantRules, mcpRegistryRules, mcpRules } from './rules/agentConfig';
import { actionsRules, extensionRules } from './rules/ciAndExtensions';
import { emudhraRules, infraRules, intelRules, pythonRules } from './rules/intel';
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

const VCS_ROOT = /^\.(git|hg|svn)(\/|$)/;
const GIT_ROOT = /^\.git(\/|$)/;

function sortFindings(xs: Finding[]): Finding[] {
  return xs.sort((a, b) => SEVERITY_RANK[b.level] - SEVERITY_RANK[a.level] || Number(a.module.slice(1)) - Number(b.module.slice(1)) || (a.path ?? '').localeCompare(b.path ?? ''));
}

/** Evaluates the loaded files. The return value contains no file content (only paths, rule IDs, fixed wording and hashes). */
export async function analyzeFiles(input: FileInput[], ioc: IocDb = IOC): Promise<EngineResult> {
  const seen = new Set<string>();
  const all = input.filter((f) => (seen.has(f.relPath) ? false : (seen.add(f.relPath), true)));
  const first = all[0]?.relPath ?? '';
  const top = first.includes('/') ? first.slice(0, first.indexOf('/')) : '';
  const root = top && all.every((f) => f.relPath.startsWith(top + '/')) ? top : '';
  // Like the CLI's inventory, the root .git / .hg / .svn are not walked (nested ones are); only what the CLI reads there
  // statically stays available to the §26 / §7 rules
  const rel = (p: string) => (root ? p.slice(root.length + 1) : p);
  const files = all.filter((f) => !VCS_ROOT.test(rel(f.relPath)));
  const vcs = all.filter((f) => GIT_ROOT.test(rel(f.relPath)));
  const ctx: RuleCtx = {
    files, byPath: new Map([...files, ...vcs].map((f) => [f.relPath, f])), ioc, specs: [], blast: [],
    viewers: { mcp: [], actions: [], extensions: [] }, errors: [], checks: new Set(), root, vcs,
    git: { configs: [], hookDirs: [], errors: [], outside: [] },
  };
  // The root .hg / .svn are not read; the root .git only through the discovery (as the CLI)
  ctx.git = gitDiscover([...files, ...vcs], root, homeLike(ctx));
  ctx.errors.push(...ctx.git.errors);
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
  pythonRules(ctx);
  phpRules(ctx);
  emudhraRules(ctx);
  intelRules(ctx);
  blastRadius(ctx);
  const skillpact = skillpactRules(ctx);

  const findings: Finding[] = [];
  const ids = new Set<string>();
  // As in the CLI emit, evidence is determined from what is at path: a file that could be read gets the hash of its content (file),
  // a directory (the parent of a loaded file) is a directory (the browser cannot compute ger-tree-v1, so detail)
  const dirs = new Set<string>();
  for (const f of files) for (let d = f.relPath; d.includes('/');) { d = d.slice(0, d.lastIndexOf('/')); dirs.add(d); }
  for (const s of ctx.specs) {
    if (s.path === null) continue;
    const fi = ctx.byPath.get(s.path);
    if (fi && s.evidenceSha === undefined && fi.sha256) s.evidenceSha = fi.sha256;
    if (!fi && dirs.has(s.path)) s.directory = true;
  }
  for (const s of ctx.specs) {
    const f = await makeFinding(s);
    if (ids.has(f.id)) continue;
    ids.add(f.id);
    findings.push(f);
  }
  // The root .git files the rules read (hooks, configs) count like the others, so an unread hook is "not scanned"
  const used = new Set([...ctx.git.configs.map((f) => f.relPath), ...vcs.filter((f) => ctx.git.hookDirs.some((d) => f.relPath.startsWith(d + '/'))).map((f) => f.relPath)]);
  const counted = [...files, ...vcs.filter((f) => used.has(f.relPath))];
  const stats = {
    files: counted.length,
    read: counted.filter((f) => f.readState === 'read').length,
    skippedSize: counted.filter((f) => f.readState === 'skipped-size').length,
    skippedBinary: counted.filter((f) => f.readState === 'skipped-binary').length,
    errors: counted.filter((f) => f.readState === 'error').length,
    zeroByteDecoys: findings.filter((f) => f.ruleId === 's17-symjack').length,
  };
  if (stats.skippedSize) ctx.errors.push({ module: 'core', reason: `ui:skipped_size:${stats.skippedSize}` });
  if (stats.errors) ctx.errors.push({ module: 'core', reason: `ui:read_error:${stats.errors}` });
  return { findings: sortFindings(findings), skillpact, blastRadius: ctx.blast.sort((a, b) => a.path.localeCompare(b.path)), viewers: ctx.viewers, errors: ctx.errors, stats, checksRun: [...ctx.checks].sort(), gitOutside: ctx.git.outside };
}

/** Evaluation of pasted text. Returns no content; only rules and counts become Findings. */
export async function analyzePaste(text: string, ioc: IocDb = IOC): Promise<Finding[]> {
  const hits = analyzePasteText(text, ioc);
  const out: Finding[] = [];
  for (const h of hits) {
    out.push(await makeFinding({ level: h.level, module: '§18', campaign: h.campaign, path: null, code: h.code, params: h.params, ruleId: h.ruleId }));
  }
  return sortFindings(out);
}

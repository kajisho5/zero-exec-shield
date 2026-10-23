// §7 / §17 / §20 / §37: MCP and agent configs, SymJack, IDE hooks, injection words in tool definitions
import { push, readable, type RuleCtx } from '../context';
import type { McpServerView } from '../types';
import { parseCodexToml } from '../toml';
import { clip, jsonPointer, parseJsonc, versionCmp, type LocatorSpec } from '../util';
import { collectDeps } from './supplyChain';

export { parseCodexToml };

const MCP_CONFIG = /(^|\/)(\.mcp\.json|mcp\.json|\.cursor\/mcp\.json|\.vscode\/mcp\.json|\.claude\/settings(\.local)?\.json|\.gemini\/settings\.json|claude_desktop_config\.json|\.claude\.json|\.codeium\/windsurf\/mcp_config\.json|\.codex\/config\.toml)$/;
// Same as CLI MCP_DANGER_RE (case-insensitive): curl / wget / base64, -c of shells (leading options such as -xc, --norc allowed),
// -e, --eval, -p, --print of node / bun, deno eval, python -c, perl / ruby -e, php -r, osascript / lua -e, pwsh -Command etc., cmd /c
const OPTS = String.raw`(\s+-\S*)*\s+`;
const B = String.raw`(^|[\s"/])`;
const HIGH_CMD = new RegExp([
  String.raw`${B}(curl|wget)([\s"]|$)|base64`,
  String.raw`${B}(ba|z|da|k|a|fi)?sh(\.exe)?${OPTS}-[a-z]*c[a-z]*(\s|$)`,
  String.raw`${B}(node|nodejs|bun)(\.exe)?${OPTS}(-e|--eval|-p|--print)([\s=]|$)|${B}deno(\.exe)?\s+ev[a]l(\s|$)`,
  String.raw`${B}python[0-9.]*(\.exe)?${OPTS}-[a-z]*c(\s|$)`,
  String.raw`${B}(perl|ruby)[0-9.]*(\.exe)?${OPTS}-[a-z]*e(\s|$)`,
  String.raw`${B}php[0-9.]*(\.exe)?${OPTS}-r(\s|$)|${B}(osascript|lua[0-9.]*)${OPTS}-e(\s|$)`,
  String.raw`${B}(pwsh|powershell)(\.exe)?(\s+\S+)*\s+[-/](c|command|e|ec|enc|encodedcommand)(\s|$)`,
  String.raw`${B}cmd(\.exe)?\s+/[ck](\s|$)`,
].join('|'), 'i');
const MED_CMD = /(^|[\s"/])(npx|uvx|bunx|pnpm dlx)([\s"]|$)/;

type Server = { name: string; command: string; args: string[]; path: (string | number)[] };
function collectServers(obj: unknown, out: Server[], name = '', path: (string | number)[] = []): void {
  if (Array.isArray(obj)) { obj.forEach((v, i) => collectServers(v, out, name, [...path, i])); return; }
  if (!obj || typeof obj !== 'object') return;
  const o = obj as Record<string, unknown>;
  // Same as the jq expression of the CLI: every object that has command. args may be an array (per element) or a string (one argument)
  if ('command' in o) {
    const str = (v: unknown) => (typeof v === 'string' ? v : JSON.stringify(v));
    const a = o['args'];
    const args = a === undefined || a === null || a === false ? [] : Array.isArray(a) ? a.map(str) : [str(a)];
    out.push({ name, command: str(o['command']), args, path });
  }
  for (const [k, v] of Object.entries(o)) if (v && typeof v === 'object') collectServers(v, out, k, [...path, k]);
}

/** Like jq, a leading BOM is accepted as strict JSON (keeps the locators format consistent with the CLI) */
const stripBom = (t: string) => (t.charCodeAt(0) === 0xfeff ? t.slice(1) : t);

function riskOf(s: { command: string; args: string[] }): 'high' | 'medium' | 'none' {
  const line = `${s.command} ${s.args.join(' ')}`;
  return HIGH_CMD.test(line) ? 'high' : MED_CMD.test(line) ? 'medium' : 'none';
}

/** Same as TASK_RUNON_PATHS of the CLI: /tasks/<i>/runOptions/runOn (value folderOpen) */
function runOnLocators(text: string): LocatorSpec[] {
  let fmt: 'json' | 'jsonc' = 'json';
  let j: unknown;
  try { j = JSON.parse(stripBom(text)); } catch { fmt = 'jsonc'; try { j = parseJsonc(text); } catch { return []; } }
  const tasks = j && typeof j === 'object' && !Array.isArray(j) ? (j as Record<string, unknown>)['tasks'] : undefined;
  if (!Array.isArray(tasks)) return [];
  const out: LocatorSpec[] = [];
  tasks.forEach((t, i) => {
    const ro = t && typeof t === 'object' && !Array.isArray(t) ? (t as Record<string, unknown>)['runOptions'] : undefined;
    if (ro && typeof ro === 'object' && !Array.isArray(ro) && (ro as Record<string, unknown>)['runOn'] === 'folderOpen') out.push({ format: fmt, pointer: jsonPointer(['tasks', i, 'runOptions', 'runOn']) });
  });
  return out;
}

/** Same as HOOK_PATHS_STR / HOOK_PATHS_RE of the CLI: entries of hooks.<Event>[i] whose command inside matches pred (/hooks/<Event>/<i>) */
export function hookLocators(text: string, pred: (cmd: string) => boolean): LocatorSpec[] {
  let fmt: 'json' | 'jsonc' = 'json';
  let j: unknown;
  try { j = JSON.parse(stripBom(text)); } catch { fmt = 'jsonc'; try { j = parseJsonc(text); } catch { return []; } }
  const hooks = j && typeof j === 'object' && !Array.isArray(j) ? (j as Record<string, unknown>)['hooks'] : undefined;
  if (!hooks || typeof hooks !== 'object' || Array.isArray(hooks)) return [];
  const cmds = (v: unknown, acc: string[] = []): string[] => {
    if (Array.isArray(v)) v.forEach((x) => cmds(x, acc));
    else if (v && typeof v === 'object') {
      const o = v as Record<string, unknown>;
      if (typeof o['command'] === 'string') acc.push(o['command']);
      Object.values(o).forEach((x) => cmds(x, acc));
    }
    return acc;
  };
  const out: LocatorSpec[] = [];
  for (const [ev, arr] of Object.entries(hooks as Record<string, unknown>)) {
    if (!Array.isArray(arr)) continue;
    arr.forEach((e, i) => { if (cmds(e).some(pred)) out.push({ format: fmt, pointer: jsonPointer(['hooks', ev, i]) }); });
  }
  return out;
}

export function mcpRules(ctx: RuleCtx): void {
  ctx.checks.add('s17-mcp-command').add('s17-symjack').add('s17-setup-mjs').add('s7-folderopen').add('s20-injection').add('s20-runtime-gate').add('s37-host-docker');
  for (const f of readable(ctx).filter((x) => MCP_CONFIG.test(x.relPath))) {
    let servers: Server[] = [];
    let parseError = false;
    // Format of locators (same as the CLI: json if readable as strict JSON, jsonc if readable only as JSONC, toml for Codex)
    let fmt: 'json' | 'jsonc' | 'toml' = 'json';
    if (f.relPath.endsWith('.toml')) {
      const r = parseCodexToml(f.text);
      servers = r.servers.map((x) => ({ ...x, path: ['mcp_servers', x.name] }));
      fmt = 'toml';
      for (const p of r.problems) ctx.errors.push({ module: '§17', reason: `codex_toml_unparsed:${p}:${f.relPath}` });
    } else {
      // VS Code etc. allow comments and trailing commas, so read as JSONC
      try { JSON.parse(stripBom(f.text)); } catch { fmt = 'jsonc'; }
      try { collectServers(parseJsonc(f.text), servers); } catch { parseError = true; }
    }
    if (parseError) {
      // An unparsable config is never reported as "no findings" (fail closed)
      ctx.errors.push({ module: '§17', reason: `mcp_config_parse_failed:${f.relPath}` });
      push(ctx, { level: 'MEDIUM', module: '§17', campaign: 'mcp-poisoning', path: f.relPath, code: 's17.config_unparsed', ruleId: 's17-mcp-command:parse-error', evidenceSha: f.sha256 });
    }
    const locs = (risk: string) => servers.filter((s) => riskOf(s) === risk).map((s) => ({ format: fmt, pointer: jsonPointer(s.path) }));
    const views: McpServerView[] = servers.map((s) => {
      const line = `${s.command} ${s.args.join(' ')}`;
      const risk = HIGH_CMD.test(line) ? 'high' : MED_CMD.test(line) ? 'medium' : 'none';
      const tokens = ctx.ioc.mcp_poisoning.suspicious_commands.filter((t) => line.includes(t));
      return { name: clip(s.name, 60), command: clip(s.command), args: clip(s.args.join(' ')), risk, tokens };
    });
    ctx.viewers.mcp.push({ path: f.relPath, servers: views, parseError });
    if (views.some((v) => v.risk === 'high')) {
      push(ctx, { level: 'HIGH', module: '§17', campaign: 'mcp-poisoning', path: f.relPath, code: 's17.dangerous_command', ruleId: 's17-mcp-command:high', evidenceSha: f.sha256, kind: 'mcp.dangerous_command', locators: locs('high') });
    }
    if (views.some((v) => v.risk === 'medium')) {
      push(ctx, { level: 'MEDIUM', module: '§17', campaign: 'mcp-poisoning', path: f.relPath, code: 's17.npx', ruleId: 's17-mcp-command:medium', evidenceSha: f.sha256, kind: 'mcp.unpinned', locators: locs('medium') });
    }
    if (/host\.docker\.internal/.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§37', campaign: 'mcp-poisoning', path: f.relPath, code: 's37.host_docker_internal', ruleId: 's37-host-docker', evidenceSha: f.sha256 });
    }
    if (/64:ff9b(:1)?::/.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§37', campaign: 'mcp-poisoning', path: f.relPath, code: 's37.nat64', ruleId: 's37-nat64', evidenceSha: f.sha256 });
    }
  }
  // SymJack: the browser cannot fetch the link target, so a decoy name with 0 bytes is "needs manual review" (§8.3)
  const decoys = ctx.ioc.mcp_poisoning.symjack.decoy_name_patterns;
  for (const f of ctx.files) {
    const rel = ctx.root ? f.relPath.slice(ctx.root.length + 1) : f.relPath;
    const decoy = decoys.some((d) => (d.endsWith('/') ? rel.startsWith(d) : f.name.toLowerCase().startsWith(d)));
    if (decoy && f.size === 0) {
      push(ctx, { level: 'HIGH', module: '§17', campaign: 'mcp-poisoning', path: f.relPath, code: 's17.symjack_zero_byte', ruleId: 's17-symjack' });
    }
  }
  // ChainDrop: setup.mjs references agent/IDE config directories (MCP config tampering; same as CLI check_s17)
  for (const f of readable(ctx).filter((x) => x.name === 'setup.mjs')) {
    if (/\.(claude|vscode|cursor)(\/|\b)/.test(f.text)) {
      push(ctx, { level: 'CRITICAL', module: '§17', campaign: 'chaindrop-keyv', path: f.relPath, code: 's17.setup_mjs', ruleId: 's17-setup-mjs', evidenceSha: f.sha256 });
    }
  }
  for (const f of readable(ctx).filter((x) => /(^|\/)\.(vscode|claude|cursor)\/tasks\.json$/.test(x.relPath))) {
    if (/"runOn"\s*:\s*"folderOpen"/.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§7', campaign: 'mcp-poisoning', path: f.relPath, code: 's7.folder_open', ruleId: 's7-folderopen', evidenceSha: f.sha256, locators: runOnLocators(f.text) });
    }
  }
  const mcpSrc = readable(ctx).filter((x) => /\.(json|js|mjs|cjs|ts|py)$/.test(x.name) && /(inputSchema|mcpServers|@modelcontextprotocol|FastMCP|mcp\.server|"tools"\s*:)/.test(x.text));
  for (const f of mcpSrc) {
    if (/(ignore (all |any )?(the )?previous instructions|do not tell the user|don't tell the user|without (telling|informing) the user)/i.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§20', campaign: 'mcp-poisoning', path: f.relPath, code: 's20.prompt_injection', ruleId: 's20-injection', evidenceSha: f.sha256 });
    }
    if (/(callCount|invocations?|callCounter|numCalls|count)\s*(>|>=)\s*[0-9]+/.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§20', campaign: 'mcp-poisoning', path: f.relPath, code: 's20.deadbugz', ruleId: 's20-runtime-gate', evidenceSha: f.sha256 });
    }
  }
}

/** Instruction files of AI agents / editors (same as CLI ai_instruction_files). */
export const isAiInstruction = (f: { name: string; relPath: string }) =>
  /^(\.cursorrules|CLAUDE\.md|CLAUDE\.local\.md|AGENTS\.md|GEMINI\.md|copilot-instructions\.md|\.windsurfrules|\.clinerules)$/.test(f.name)
  || /(^|\/)\.cursor\/rules\/[^/]+$|(^|\/)\.clinerules\/.+|(^|\/)\.github\/instructions\/.+|(^|\/)\.claude\/(.+\/)?[^/]+\.md$/.test(f.relPath);

/** §7 Invisible characters, BiDi control characters and homoglyphs in AI instruction files. */
export function aiAssistantRules(ctx: RuleCtx): void {
  ctx.checks.add('s7-invisible').add('s7-homoglyph');
  const targets = readable(ctx).filter(isAiInstruction);
  for (const f of targets) {
    // Embedding with variation selectors (U+FE00–FE0D, U+E0100–E01EF, 2 or more consecutive U+FE00–FE0F) is covered too (same as CLI §7)
    if (/[​-‏‪-‮⁠-⁤⁦-⁩]|[\u{E0000}-\u{E007F}]|[\u{FE00}-\u{FE0D}]|[\u{E0100}-\u{E01EF}]|[\u{FE00}-\u{FE0F}]{2}/u.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§7', campaign: null, path: f.relPath, code: 's7.invisible_chars', ruleId: 's7-invisible', evidenceSha: f.sha256 });
    }
    if (/[A-Za-z][Ͱ-ϿЀ-ӿ]|[Ͱ-ϿЀ-ӿ][A-Za-z]/u.test(f.text)) {
      push(ctx, { level: 'MEDIUM', module: '§7', campaign: null, path: f.relPath, code: 's7.homoglyph', ruleId: 's7-homoglyph', evidenceSha: f.sha256 });
    }
  }
}

/** §37 MCP registries (the part of CLI check_s37 that can be evaluated from loaded files): traces of MCP-POISON and CVEs of MCP-related dependencies. */
export function mcpRegistryRules(ctx: RuleCtx): void {
  ctx.checks.add('s37-marker').add('s37-mcp-cves').add('s37-mcp-deps');
  for (const f of readable(ctx).filter((x) => /\.(json|ya?ml|toml|js|ts|py|md)$/.test(x.name) && x.text.includes('MCP-POISON'))) {
    push(ctx, { level: 'HIGH', module: '§37', campaign: 'mcp-poisoning', path: f.relPath, code: 's37.specter', ruleId: 's37-marker', evidenceSha: f.sha256 });
  }
  const deps = collectDeps(ctx);
  const cves = (ctx.ioc.mcp_poisoning['mcp_cves'] ?? []) as { id: string; eco?: string; package?: string; fixed?: string }[];
  for (const c of cves) {
    if (!c.package || !c.fixed) continue;
    for (const d of deps) {
      if (d.eco !== c.eco || d.name !== c.package || d.version === '' || versionCmp(d.version, c.fixed) >= 0) continue;
      push(ctx, { level: 'HIGH', module: '§37', campaign: 'mcp-poisoning', path: d.path, code: 's37.mcp_cve', params: { cve: c.id, fixed: c.fixed, package: c.package, version: d.version }, ruleId: `s37-mcp-cves:${c.id}:${d.version}`, evidenceSha: d.sha, kind: 'runtime.cve' });
    }
  }
  // MCP-related CVEs with no fixed version defined in ioc report the possibly affected dependencies as needing review
  for (const d of deps) {
    const hit = (d.eco === 'npm' && (d.name === '@modelcontextprotocol/sdk' || /appium.*mcp|mcp.*appium/.test(d.name) || d.name === '@modelcontextprotocol/server-everything' || /gitlab-mcp/.test(d.name)))
      || (d.eco === 'pypi' && (d.name === 'mcp' || d.name === 'mcp-server-fetch' || d.name === 'fastmcp'))
      || (d.eco === 'go' && /stacklok\/toolhive/.test(d.name));
    if (hit) push(ctx, { level: 'MEDIUM', module: '§37', campaign: 'mcp-poisoning', path: d.path, code: 's37.mcp_dependency', params: { package: d.name, version: d.version }, ruleId: `s37-mcp-deps:${d.name}@${d.version}`, evidenceSha: d.sha });
  }
}

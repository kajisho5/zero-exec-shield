// §7 / §17 / §20 / §37: MCP and agent configs, SymJack, IDE hooks, injection words in tool definitions
import { push, readable, rootRel, type RuleCtx } from '../context';
import type { FileInput, McpServerView } from '../types';
import { parseCodexToml } from '../toml';
import { asciiLower, clip, jsonPointer, parseJsonc, versionCmp, type LocatorSpec } from '../util';
import { INVISIBLE_7 } from '../hiddenChars';
import { collectDeps } from './supplyChain';

export { parseCodexToml };

const MCP_CONFIG = /(^|\/)(\.mcp\.json|mcp\.json|\.cursor\/mcp\.json|\.vscode\/mcp\.json|\.claude\/settings(\.local)?\.json|\.gemini\/settings\.json|claude_desktop_config\.json|\.claude\.json|\.codeium\/windsurf\/mcp_config\.json|\.codex\/config\.toml)$/;
// Same as CLI MCP_DANGER_RE (case-insensitive): curl / wget / base64, -c of shells (leading options such as -xc, --norc allowed),
// -e, --eval, -p, --print of node / bun, deno eval, python -c, perl / ruby -e, php -r, osascript / lua -e, pwsh -Command etc., cmd /c
const OPTS = String.raw`([\t\v\f\r ]+-[^\t\n\v\f\r ]*)*[\t\v\f\r ]+`;
const B = String.raw`(^|[\t\v\f\r "/])`;
const HIGH_CMD = new RegExp([
  String.raw`${B}(curl|wget)([\t\v\f\r "]|$)|base64`,
  String.raw`${B}(ba|z|da|k|a|fi)?sh(\.exe)?${OPTS}-[a-z]*c[a-z]*([\t\v\f\r ]|$)`,
  String.raw`${B}(node|nodejs|bun)(\.exe)?${OPTS}(-e|--eval|-p|--print)([\t\v\f\r =]|$)|${B}deno(\.exe)?[\t\v\f\r ]+ev[a]l([\t\v\f\r ]|$)`,
  String.raw`${B}python[0-9.]*(\.exe)?${OPTS}-[a-z]*c([\t\v\f\r ]|$)`,
  String.raw`${B}(perl|ruby)[0-9.]*(\.exe)?${OPTS}-[a-z]*e([\t\v\f\r ]|$)`,
  String.raw`${B}php[0-9.]*(\.exe)?${OPTS}-r([\t\v\f\r ]|$)|${B}(osascript|lua[0-9.]*)${OPTS}-e([\t\v\f\r ]|$)`,
  String.raw`${B}(pwsh|powershell)(\.exe)?([\t\v\f\r ]+[^\t\n\v\f\r ]+)*[\t\v\f\r ]+[-/](c|command|e|ec|enc|encodedcommand)([\t\v\f\r ]|$)`,
  String.raw`${B}cmd(\.exe)?[\t\v\f\r ]+/[ck]([\t\v\f\r ]|$)`,
].join('|'), 'i');
const MED_CMD = /(^|[\t\v\f\r "/])(npx|uvx|bunx|pnpm dlx)([\t\v\f\r "]|$)/;

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


/** Agent config files whose top-level "hooks" holds agent hooks (the CLI's AGENT_HOOK_FILES_RE) */
const AGENT_HOOK_FILE = /(^|\/)\.(claude|cursor|gemini)\/(settings(\.local)?|hooks)\.json$/;
/** An object inside a hook entry /hooks/<Event>/<i>/… is a hook, not an MCP server (the CLI's mcpq with $hk == 1) */
const inHookEntry = (p: (string | number)[]) => p.length >= 3 && p[0] === 'hooks' && typeof p[1] === 'string' && typeof p[2] === 'number';

type HookEntry = { pointer: string; cmds: string[]; lines: string[] };
/** Same as HOOK_ENTRY_CMDS of the CLI: the entries hooks.<Event>[i] in order, with the .command strings inside each and the
 *  lines of command + args of every object inside it that has command (as collectServers). null when the text does not parse */
function hookEntries(text: string): { fmt: 'json' | 'jsonc'; entries: HookEntry[] } | null {
  let fmt: 'json' | 'jsonc' = 'json';
  let j: unknown;
  try { j = JSON.parse(text); } catch { fmt = 'jsonc'; try { j = parseJsonc(text); } catch { return null; } }
  const hooks = j && typeof j === 'object' && !Array.isArray(j) ? (j as Record<string, unknown>)['hooks'] : undefined;
  const entries: HookEntry[] = [];
  if (!hooks || typeof hooks !== 'object' || Array.isArray(hooks)) return { fmt, entries };
  for (const [ev, arr] of Object.entries(hooks as Record<string, unknown>)) {
    if (!Array.isArray(arr)) continue;
    arr.forEach((e, i) => {
      const cmds: string[] = [];
      const objs: Server[] = [];
      const walk = (v: unknown): void => {
        if (Array.isArray(v)) v.forEach(walk);
        else if (v && typeof v === 'object') {
          const o = v as Record<string, unknown>;
          if (typeof o['command'] === 'string') cmds.push(o['command']);
          Object.values(o).forEach(walk);
        }
      };
      walk(e);
      collectServers(e, objs);
      const lines = objs.flatMap((s) => `${s.command} ${s.args.join(' ')}`.split('\n'));
      entries.push({ pointer: jsonPointer(['hooks', ev, i]), cmds, lines });
    });
  }
  return { fmt, entries };
}

function riskOf(s: { command: string; args: string[] }): 'high' | 'medium' | 'none' {
  const line = `${s.command} ${s.args.join(' ')}`;
  return HIGH_CMD.test(line) ? 'high' : MED_CMD.test(line) ? 'medium' : 'none';
}

/** Same as TASK_RUNON_PATHS of the CLI: /tasks/<i>/runOptions/runOn (value folderOpen) */
function runOnLocators(text: string): LocatorSpec[] {
  let fmt: 'json' | 'jsonc' = 'json';
  let j: unknown;
  try { j = JSON.parse(text); } catch { fmt = 'jsonc'; try { j = parseJsonc(text); } catch { return []; } }
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
  try { j = JSON.parse(text); } catch { fmt = 'jsonc'; try { j = parseJsonc(text); } catch { return []; } }
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
  ctx.checks.add('s17-mcp-command').add('s17-agent-hook').add('s17-symjack').add('s17-setup-mjs').add('s7-folderopen').add('s20-injection').add('s20-runtime-gate').add('s37-host-docker');
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
      try { JSON.parse(f.text); } catch { fmt = 'jsonc'; }
      try { collectServers(parseJsonc(f.text), servers); } catch { parseError = true; }
      // Hook entries are judged by the agent-hook check below (which also applies HIGH_CMD to them)
      if (AGENT_HOOK_FILE.test(f.relPath)) servers = servers.filter((s) => !inHookEntry(s.path));
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
  // Agent hooks (the CLI's check_s17): a hook entry /hooks/<Event>/<i> of a .claude / .cursor / .gemini settings or hooks
  //   file is reported when (a) the file has "hooks" and a command with network access or obfuscation (preselection) and
  //   a .command string inside the entry matches, or (b) the command + args of an object inside the entry match HIGH_CMD
  //   on some line (the rule the MCP check applied to hooks before it skipped them; no preselection). npx / uvx in a hook
  //   is not reported. A curl in mcpServers is not a hook. When the file does not parse, the preselection decides
  const HOOK_RE = /(curl|wget|base64|nc |\/dev\/tcp)/;
  for (const f of readable(ctx).filter((x) => AGENT_HOOK_FILE.test(x.relPath))) {
    const gate = /"hooks"[\t\v\f\r ]*:/.test(f.text) && /"command"[\t\v\f\r ]*:[\t\v\f\r ]*"[^"\n]*(curl|wget|base64|nc |\/dev\/tcp)/.test(f.text);
    const parsed = f.text.includes('"hooks"') ? hookEntries(f.text) : null;
    const locators: LocatorSpec[] = (parsed?.entries ?? [])
      .filter((e) => (gate && e.cmds.some((c) => HOOK_RE.test(c))) || e.lines.some((l) => l !== '' && HIGH_CMD.test(l)))
      .map((e) => ({ format: parsed!.fmt, pointer: e.pointer }));
    if (!locators.length && !(gate && !parsed)) continue;
    push(ctx, { level: 'HIGH', module: '§17', campaign: 'mcp-poisoning', path: f.relPath, code: 's17.agent_hook', ruleId: 's17-agent-hook', evidenceSha: f.sha256, locators });
  }
  // SymJack: the browser cannot fetch the link target, so a decoy name with 0 bytes is "needs manual review" (§8.3)
  const decoys = ctx.ioc.mcp_poisoning.symjack.decoy_name_patterns;
  for (const f of ctx.files) {
    const rel = ctx.root ? f.relPath.slice(ctx.root.length + 1) : f.relPath;
    const decoy = decoys.some((d) => (d.endsWith('/') ? rel.startsWith(d) : asciiLower(f.name).startsWith(d)));
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
    if (/"runOn"[\t\v\f\r ]*:[\t\v\f\r ]*"folderOpen"/.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§7', campaign: 'mcp-poisoning', path: f.relPath, code: 's7.folder_open', ruleId: 's7-folderopen', evidenceSha: f.sha256, locators: runOnLocators(f.text) });
    }
  }
  // the CLI's mcp_source_files (node_modules/typescript and node_modules/@types are not MCP servers)
  const mcpSrc = readable(ctx).filter((x) => /\.(json|js|mjs|cjs|ts|py)$/.test(x.name) && !/(^|\/)node_modules\/(typescript|@types)\//.test(rootRel(ctx, x)) && /(inputSchema|mcpServers|@modelcontextprotocol|FastMCP|mcp\.server|"tools"[\t\v\f\r ]*:)/.test(x.text));
  for (const f of mcpSrc) {
    if (/(ignore (all |any )?(the )?previous instructions|do not tell the user|don't tell the user|without (telling|informing) the user)/i.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§20', campaign: 'mcp-poisoning', path: f.relPath, code: 's20.prompt_injection', ruleId: 's20-injection', evidenceSha: f.sha256 });
    }
    if (/(callCount|invocations?|callCounter|numCalls|count)[\t\v\f\r ]*(>|>=)[\t\v\f\r ]*[0-9]+/.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§20', campaign: 'mcp-poisoning', path: f.relPath, code: 's20.deadbugz', ruleId: 's20-runtime-gate', evidenceSha: f.sha256 });
    }
  }
}

/** Instruction files of AI agents / editors (same as CLI ai_instruction_files). */
export const isAiInstruction = (f: { name: string; relPath: string }) =>
  /^(\.cursorrules|CLAUDE\.md|CLAUDE\.local\.md|AGENTS\.md|GEMINI\.md|copilot-instructions\.md|\.windsurfrules|\.clinerules)$/.test(f.name)
  || /(^|\/)\.cursor\/rules\/[^/]+$|(^|\/)\.clinerules\/.+|(^|\/)\.github\/instructions\/.+|(^|\/)\.claude\/(.+\/)?[^/]+\.md$/.test(f.relPath);


/** §7 Invisible characters, BiDi control characters and homoglyphs in AI instruction files; Git hooks. */
export function aiAssistantRules(ctx: RuleCtx): void {
  ctx.checks.add('s7-invisible').add('s7-homoglyph').add('s7-git-hook');
  // Git hooks (CLI check_s7): every non-sample file directly in a hook directory found by gitDiscover (the root .git,
  // nested .git directories, gitdir: files, the commondir of a worktree; the CLI's "$hookdir"/* glob: no dot files).
  // A hook the browser could not read (over 2 MiB, read error) is HIGH s7.git_hook_unread: the CLI reads it and would
  // report HIGH if it is malicious, so it is not shown as a plain MEDIUM hook (and it counts as not scanned)
  const hookFile = (x: FileInput) => ctx.git.hookDirs.includes(x.relPath.slice(0, x.relPath.lastIndexOf('/'))) && !x.name.startsWith('.') && !x.name.endsWith('.sample');
  for (const f of [...ctx.vcs, ...ctx.files].filter(hookFile)) {
    if (f.text === null) {
      push(ctx, { level: 'HIGH', module: '§7', campaign: null, path: f.relPath, code: 's7.git_hook_unread', ruleId: 's7-git-hook' });
      continue;
    }
    const bad = /(curl|wget|base64|nc |\/dev\/tcp|python[0-9.]* -c|node -e)/.test(f.text);
    push(ctx, { level: bad ? 'HIGH' : 'MEDIUM', module: '§7', campaign: null, path: f.relPath, code: bad ? 's7.git_hook_suspicious' : 's7.git_hook', ruleId: 's7-git-hook', evidenceSha: f.sha256 });
  }
  // §41 (the CLI's check_s41): AI instruction files together with a Git hook (any non-sample file under a hook directory,
  //   dot files and subdirectories included, as the CLI's find) or an agent hook config ("hooks" in a .claude / .cursor /
  //   .gemini settings or hooks file) in the same tree: HIGH on the folder itself
  ctx.checks.add('s41-instructions-hooks');
  const hasInstr = ctx.files.some(isAiInstruction);
  const hasHook = [...ctx.vcs, ...ctx.files].some((x) => ctx.git.hookDirs.some((d) => x.relPath.startsWith(d + '/')) && !x.name.endsWith('.sample'));
  const hasAgentHook = readable(ctx).some((x) => /(^|\/)\.(claude|cursor|gemini)\/(settings(\.local)?|hooks)\.json$/.test(x.relPath) && x.text.includes('"hooks"'));
  if (hasInstr && (hasHook || hasAgentHook)) push(ctx, { level: 'HIGH', module: '§41', campaign: null, path: ctx.root || null, code: 's41.instructions_and_hooks', ruleId: 's41-instructions-hooks' });
  const targets = readable(ctx).filter(isAiInstruction);
  for (const f of targets) {
    // Embedding with variation selectors (U+FE00–FE0D, U+E0100–E01EF, 2 or more consecutive U+FE00–FE0F) is covered too (same as CLI §7)
    if (INVISIBLE_7.test(f.text)) {
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

// §7 / §17 / §20 / §37: MCP・エージェント設定、SymJack、IDE フック、ツール定義の注入語
import { push, readable, type RuleCtx } from '../context';
import type { McpServerView } from '../types';
import { parseCodexToml } from '../toml';
import { clip, parseJsonc, versionCmp } from '../util';
import { collectDeps } from './supplyChain';

export { parseCodexToml };

const MCP_CONFIG = /(^|\/)(\.mcp\.json|mcp\.json|\.cursor\/mcp\.json|\.vscode\/mcp\.json|\.claude\/settings(\.local)?\.json|\.gemini\/settings\.json|claude_desktop_config\.json|\.claude\.json|\.codeium\/windsurf\/mcp_config\.json|\.codex\/config\.toml)$/;
const HIGH_CMD = /(^|[\s"/])(curl|wget)([\s"]|$)|bash -c|sh -c|powershell(\.exe)? .*-(e|enc|encodedcommand)\s|node -e|python[0-9.]* -c|base64/;
const MED_CMD = /(^|[\s"/])(npx|uvx|bunx|pnpm dlx)([\s"]|$)/;

function collectServers(obj: unknown, out: { name: string; command: string; args: string[] }[], name = ''): void {
  if (Array.isArray(obj)) { obj.forEach((v) => collectServers(v, out, name)); return; }
  if (!obj || typeof obj !== 'object') return;
  const o = obj as Record<string, unknown>;
  // CLI の jq 式と同じ: command を持つ全オブジェクト。args は配列（要素ごと）でも文字列（1 引数）でもよい
  if ('command' in o) {
    const str = (v: unknown) => (typeof v === 'string' ? v : JSON.stringify(v));
    const a = o['args'];
    const args = a === undefined || a === null || a === false ? [] : Array.isArray(a) ? a.map(str) : [str(a)];
    out.push({ name, command: str(o['command']), args });
  }
  for (const [k, v] of Object.entries(o)) if (v && typeof v === 'object') collectServers(v, out, k);
}

export function mcpRules(ctx: RuleCtx): void {
  ctx.checks.add('s17-mcp-command').add('s17-symjack').add('s17-setup-mjs').add('s7-folderopen').add('s20-injection').add('s20-runtime-gate').add('s37-host-docker');
  for (const f of readable(ctx).filter((x) => MCP_CONFIG.test(x.relPath))) {
    let servers: { name: string; command: string; args: string[] }[] = [];
    let parseError = false;
    if (f.relPath.endsWith('.toml')) {
      const r = parseCodexToml(f.text);
      servers = r.servers;
      for (const p of r.problems) ctx.errors.push({ module: '§17', reason: `codex_toml_unparsed:${p}:${f.relPath}` });
    } else {
      // VS Code 等はコメント・末尾カンマを許すため JSONC として読む
      try { collectServers(parseJsonc(f.text), servers); } catch { parseError = true; }
    }
    if (parseError) {
      // 解析できない設定を「検出なし」にしない（fail closed）
      ctx.errors.push({ module: '§17', reason: `mcp_config_parse_failed:${f.relPath}` });
      push(ctx, { level: 'MEDIUM', module: '§17', campaign: 'mcp-poisoning', path: f.relPath, detail: 'MCP/エージェント設定を解析できません（未判定。command/args を手動または CLI で確認）', ruleId: 's17-mcp-command:parse-error', evidenceSha: f.sha256 });
    }
    const views: McpServerView[] = servers.map((s) => {
      const line = `${s.command} ${s.args.join(' ')}`;
      const risk = HIGH_CMD.test(line) ? 'high' : MED_CMD.test(line) ? 'medium' : 'none';
      const tokens = ctx.ioc.mcp_poisoning.suspicious_commands.filter((t) => line.includes(t));
      return { name: clip(s.name, 60), command: clip(s.command), args: clip(s.args.join(' ')), risk, tokens };
    });
    ctx.viewers.mcp.push({ path: f.relPath, servers: views, parseError });
    if (views.some((v) => v.risk === 'high')) {
      push(ctx, { level: 'HIGH', module: '§17', campaign: 'mcp-poisoning', path: f.relPath, detail: 'MCP/エージェント設定の command/args に危険なコマンド（curl/wget/bash -c/powershell -enc/node -e）', ruleId: 's17-mcp-command:high', evidenceSha: f.sha256 });
    }
    if (views.some((v) => v.risk === 'medium')) {
      push(ctx, { level: 'MEDIUM', module: '§17', campaign: 'mcp-poisoning', path: f.relPath, detail: 'MCP の command が npx/uvx（実行時に最新版を取得。バージョン固定を確認）', ruleId: 's17-mcp-command:medium', evidenceSha: f.sha256 });
    }
    if (/host\.docker\.internal/.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§37', campaign: 'mcp-poisoning', path: f.relPath, detail: 'MCP 設定が host.docker.internal を参照（コンテナからホストへの横移動）', ruleId: 's37-host-docker', evidenceSha: f.sha256 });
    }
    if (/64:ff9b(:1)?::/.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§37', campaign: 'mcp-poisoning', path: f.relPath, detail: 'MCP 設定が IPv6 NAT64 レンジを参照（SSRF フィルタ回避）', ruleId: 's37-nat64', evidenceSha: f.sha256 });
    }
  }
  // SymJack: ブラウザはリンク先を取得できないため、デコイ名かつ 0 バイトを「要手動確認」とする（§8.3）
  const decoys = ctx.ioc.mcp_poisoning.symjack.decoy_name_patterns;
  for (const f of ctx.files) {
    const rel = ctx.root ? f.relPath.slice(ctx.root.length + 1) : f.relPath;
    const decoy = decoys.some((d) => (d.endsWith('/') ? rel.startsWith(d) : f.name.toLowerCase().startsWith(d)));
    if (decoy && f.size === 0) {
      push(ctx, { level: 'HIGH', module: '§17', campaign: 'mcp-poisoning', path: f.relPath, detail: 'デコイ名かつ 0 バイト：SymJack 疑い（要手動確認。CLI で readlink -f）', ruleId: 's17-symjack' });
    }
  }
  // ChainDrop: setup.mjs がエージェント/IDE 設定ディレクトリを参照（MCP 設定改ざん。CLI check_s17 と同じ）
  for (const f of readable(ctx).filter((x) => x.name === 'setup.mjs')) {
    if (/\.(claude|vscode|cursor)(\/|\b)/.test(f.text)) {
      push(ctx, { level: 'CRITICAL', module: '§17', campaign: 'chaindrop-keyv', path: f.relPath, detail: 'setup.mjs がエージェント/IDE 設定ディレクトリを参照（MCP 設定改ざん）', ruleId: 's17-setup-mjs', evidenceSha: f.sha256 });
    }
  }
  for (const f of readable(ctx).filter((x) => /(^|\/)\.(vscode|claude|cursor)\/tasks\.json$/.test(x.relPath))) {
    if (/"runOn"\s*:\s*"folderOpen"/.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§7', campaign: 'mcp-poisoning', path: f.relPath, detail: 'フォルダを開くだけで自動実行されるタスク（runOn: folderOpen）', ruleId: 's7-folderopen', evidenceSha: f.sha256 });
    }
  }
  const mcpSrc = readable(ctx).filter((x) => /\.(json|js|mjs|cjs|ts|py)$/.test(x.name) && /(inputSchema|mcpServers|@modelcontextprotocol|FastMCP|mcp\.server|"tools"\s*:)/.test(x.text));
  for (const f of mcpSrc) {
    if (/(ignore (all |any )?(the )?previous instructions|do not tell the user|don't tell the user|without (telling|informing) the user)/i.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§20', campaign: 'mcp-poisoning', path: f.relPath, detail: 'MCP ツール定義にプロンプトインジェクション文言', ruleId: 's20-injection', evidenceSha: f.sha256 });
    }
    if (/(callCount|invocations?|callCounter|numCalls|count)\s*(>|>=)\s*[0-9]+/.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§20', campaign: 'mcp-poisoning', path: f.relPath, detail: 'Deadbugz 型ランタイムゲート（呼び出し回数による条件分岐）', ruleId: 's20-runtime-gate', evidenceSha: f.sha256 });
    }
  }
}

/** §7 AI 指示ファイルの不可視文字・BiDi 制御文字・ホモグリフ。 */
export function aiAssistantRules(ctx: RuleCtx): void {
  ctx.checks.add('s7-invisible').add('s7-homoglyph');
  const targets = readable(ctx).filter((x) => /^(\.cursorrules|CLAUDE\.md|copilot-instructions\.md)$/.test(x.name) || /(^|\/)\.cursor\/rules\/[^/]+$/.test(x.relPath));
  for (const f of targets) {
    if (/[​-‏‪-‮⁠-⁤⁦-⁩]|[\u{E0000}-\u{E007F}]/u.test(f.text)) {
      push(ctx, { level: 'HIGH', module: '§7', campaign: null, path: f.relPath, detail: 'AI 指示ファイルに不可視文字 / Unicode BiDi 制御文字', ruleId: 's7-invisible', evidenceSha: f.sha256 });
    }
    if (/[A-Za-z][Ͱ-ϿЀ-ӿ]|[Ͱ-ϿЀ-ӿ][A-Za-z]/u.test(f.text)) {
      push(ctx, { level: 'MEDIUM', module: '§7', campaign: null, path: f.relPath, detail: 'ラテン文字と混在するキリル/ギリシャ文字（ホモグリフ疑い）', ruleId: 's7-homoglyph', evidenceSha: f.sha256 });
    }
  }
}

/** §37 MCP レジストリ（CLI check_s37 のうち投入ファイルで判定できる部分）: MCP-POISON の痕跡と、MCP 関連依存の CVE。 */
export function mcpRegistryRules(ctx: RuleCtx): void {
  ctx.checks.add('s37-marker').add('s37-mcp-cves').add('s37-mcp-deps');
  for (const f of readable(ctx).filter((x) => /\.(json|ya?ml|toml|js|ts|py|md)$/.test(x.name) && x.text.includes('MCP-POISON'))) {
    push(ctx, { level: 'HIGH', module: '§37', campaign: 'mcp-poisoning', path: f.relPath, detail: 'SPECTER MCP-POISON の痕跡', ruleId: 's37-marker', evidenceSha: f.sha256 });
  }
  const deps = collectDeps(ctx);
  const cves = (ctx.ioc.mcp_poisoning['mcp_cves'] ?? []) as { id: string; eco?: string; package?: string; fixed?: string }[];
  for (const c of cves) {
    if (!c.package || !c.fixed) continue;
    for (const d of deps) {
      if (d.eco !== c.eco || d.name !== c.package || d.version === '' || versionCmp(d.version, c.fixed) >= 0) continue;
      push(ctx, { level: 'HIGH', module: '§37', campaign: 'mcp-poisoning', path: d.path, detail: `${c.package}@${d.version} は ${c.id} の影響範囲（修正版 ${c.fixed}）`, ruleId: `s37-mcp-cves:${c.id}:${d.version}`, evidenceSha: d.sha });
    }
  }
  // ioc に修正版が未定義の MCP 関連 CVE は、該当しうる依存を要確認として出す
  for (const d of deps) {
    const hit = (d.eco === 'npm' && (d.name === '@modelcontextprotocol/sdk' || /appium.*mcp|mcp.*appium/.test(d.name) || d.name === '@modelcontextprotocol/server-everything' || /gitlab-mcp/.test(d.name)))
      || (d.eco === 'pypi' && (d.name === 'mcp' || d.name === 'mcp-server-fetch' || d.name === 'fastmcp'))
      || (d.eco === 'go' && /stacklok\/toolhive/.test(d.name));
    if (hit) push(ctx, { level: 'MEDIUM', module: '§37', campaign: 'mcp-poisoning', path: d.path, detail: `MCP 関連依存 ${d.name}@${d.version}: CVE-2026-104850/104120/111767/59951/61559/52869/58500, GO-2026-5996/6002 の該当可否を確認（ioc に修正版未定義）`, ruleId: `s37-mcp-deps:${d.name}@${d.version}`, evidenceSha: d.sha });
  }
}

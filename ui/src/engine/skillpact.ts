// §49 SkillPact（CLI check_skillpact と同じ規則をブラウザで再現）
// - 契約・ポリシー・前バージョン契約は JSON.parse のみ。スキル本体は実行しない
// - L2 記録は存在と SHA-256 のみ、L3 署名は署名ファイルの存在のみ（検証しない・信頼判定に使わない）
import { push, type RuleCtx } from './context';
import type { Effect, FileInput, RuleResult, Severity, SkillPactAnalysis, SkillPactFindingField } from './types';
import { EFFECTS, SEVERITY_RANK } from './types';
import { basename, dirname, ere, splitMarkdown, versionCmp } from './util';

type Contract = Record<string, unknown>;
const ORDER = ['exec', 'network', 'write', 'read', 'secrets', 'spend', 'persist', 'longrun'];
const sortEffects = (xs: Iterable<string>) => [...new Set(xs)].sort((a, b) => (ORDER.indexOf(a) + 99) % 99 - (ORDER.indexOf(b) + 99) % 99 || a.localeCompare(b));
const RISKY = ['exec', 'network', 'secrets'];
const SCRIPT_FENCES = new Set(['bash', 'sh', 'shell', 'zsh', 'fish', 'console', 'shell-session', 'powershell', 'ps1', 'pwsh', 'cmd', 'bat', 'python', 'python3', 'py', 'js', 'javascript', 'node', 'mjs', 'ts', 'typescript', 'ruby', 'rb', 'perl', 'php']);

function normEffect(e: unknown): string {
  if (typeof e === 'string') return e;
  if (e && typeof e === 'object') {
    const o = e as Record<string, unknown>;
    const base = String(o['effect'] ?? o['type'] ?? o['name'] ?? '');
    return o['scope'] != null ? `${base}:${String(o['scope'])}` : base;
  }
  return String(e);
}

function tokens(c: Contract): string[] {
  const own = Array.isArray(c['effects']) ? (c['effects'] as unknown[]).map(normEffect) : [];
  const ops = Array.isArray(c['operations']) ? (c['operations'] as Record<string, unknown>[]).flatMap((o) => (Array.isArray(o['effects']) ? (o['effects'] as unknown[]).map(normEffect) : [])) : [];
  return [...new Set([...own, ...ops].filter(Boolean))].sort();
}
const baseOf = (t: string) => t.split(':')[0] ?? t;
const str = (v: unknown): string | null => (v == null ? null : typeof v === 'object' ? ((v as Record<string, unknown>)['name'] as string) ?? JSON.stringify(v) : String(v));

function parse(f: FileInput | undefined): Contract | null | 'invalid' {
  if (!f) return null;
  if (f.text == null) return 'invalid';
  try {
    const v = JSON.parse(f.text) as unknown;
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Contract) : 'invalid';
  } catch {
    return 'invalid';
  }
}

function skillDirs(ctx: RuleCtx, contractNames: string[]): string[] {
  const dirs = new Set<string>();
  for (const f of ctx.files) {
    if (f.name === 'SKILL.md' || f.name === 'skill.contract.json') dirs.add(dirname(f.relPath));
    if (/(^|\/)\.skillpact\/contract\.json$/.test(f.relPath)) dirs.add(dirname(dirname(f.relPath)));
  }
  void contractNames;
  return [...dirs].sort();
}

function skillFiles(ctx: RuleCtx, dir: string, all: string[]): FileInput[] {
  const nested = all.filter((d) => d !== dir && (dir === '' || d.startsWith(dir + '/')));
  return ctx.files.filter((f) => (dir === '' || f.relPath.startsWith(dir + '/')) && !nested.some((n) => f.relPath.startsWith(n + '/')));
}

export function skillpactRules(ctx: RuleCtx): SkillPactAnalysis[] {
  ctx.checks.add('s49');
  const sp = ctx.ioc.skillpact;
  const dirs = skillDirs(ctx, sp.contract_filenames);
  const threshold = sp.trust_model.diff_anomaly_detection?.threshold ?? 0.3;
  const patterns = Object.fromEntries(Object.entries(sp.observed_effect_patterns).map(([k, v]) => [k, ere(v.join('|'))]));
  const destr = sp.destructive_markers.map((m) => (m.includes(' | ') ? ere(`${esc(m.split(' | ')[0] ?? '')}[^|\\n]*\\|\\s*${esc(m.split(' | ')[1] ?? '')}`, 'i') : ere(esc(m).replace(/ /g, '\\s+'), 'i')));
  const persist = sp.persistence_markers.map((m) => (m === 'registry run' ? /registry\s+run|CurrentVersion\\Run|reg\s+add[^\n]*\\Run/i : ere(esc(m).replace(/ /g, '\\s+'), 'i')));
  const prose = sp.prose_claims.map((c) => ({ ...c, re: ere(c.patterns.map(esc).join('|'), 'i') }));
  // 前バージョン比較用: 投入されたすべての契約（ブラウザはレジストリを取得しない）
  const allContracts = ctx.files
    .filter((f) => sp.contract_filenames.some((n) => f.relPath === n || f.relPath.endsWith('/' + n)))
    .map((f) => ({ f, c: parse(f) }))
    .filter((x): x is { f: FileInput; c: Contract } => x.c !== null && x.c !== 'invalid');

  const out: SkillPactAnalysis[] = [];
  for (const dir of dirs) {
    const files = skillFiles(ctx, dir, dirs);
    const inSkill = (rel: string) => ctx.byPath.get(dir ? `${dir}/${rel}` : rel);
    const cfile = sp.contract_filenames.map(inSkill).find(Boolean);
    let code = '';
    let proseText = '';
    let tools = '';
    let scripts = false;
    let fences: string[] = [];
    for (const f of files) {
      if (/(^|\/)\.skillpact\/|(^|\/)(skill\.contract\.json|policy-v0\.8\.json|l2-test-record\.json)$|\.(sig|bundle)$/.test(f.relPath)) continue;
      if (f.text == null) continue;
      if (f.name.endsWith('.md')) {
        const m = splitMarkdown(f.text);
        code += '\n' + m.code + '\n' + m.frontmatter;
        proseText += '\n' + m.prose;
        fences = fences.concat(m.fenceLangs);
        tools += m.frontmatter.split('\n').filter((l) => l.startsWith('allowed-tools:')).join('\n');
      } else if (sp.script_extensions.includes(f.name.split('.').pop() ?? '') || f.text.startsWith('#!')) {
        scripts = true;
        code += '\n' + f.text;
      } else if (/\.(json|ya?ml|toml|ini|cfg)$/.test(f.name)) {
        code += '\n' + f.text;
      }
    }
    const observed = new Set<Effect>(['read']);
    for (const e of ['exec', 'network', 'write', 'secrets', 'spend'] as Effect[]) {
      if (patterns[e]?.test(code)) observed.add(e);
    }
    if (scripts || fences.some((l) => SCRIPT_FENCES.has(l)) || /(^|[^A-Za-z])Bash([^A-Za-z]|$)/.test(tools)) observed.add('exec');
    if (/(WebFetch|WebSearch)/.test(tools)) observed.add('network');
    if (/(^|[^A-Za-z])(Write|Edit|MultiEdit|NotebookEdit)([^A-Za-z]|$)/.test(tools)) observed.add('write');
    const destructive = destr.some((r) => r?.test(code));
    const persistence = persist.some((r) => r?.test(code));
    if (persistence) observed.add('write');
    if (destructive) { observed.add('exec'); observed.add('write'); }
    const observedSorted = EFFECTS.filter((e) => observed.has(e));

    const a: SkillPactAnalysis = {
      skillId: dir || '.', name: basename(dir) || '.',
      contract: { found: !!cfile, path: cfile?.relPath ?? null, parseError: false, schemaVersion: null, supported: false },
      author: null, version: null, level: null, signed: false, l2Tested: false, declared: [], declaredTokens: [],
      observed: observedSorted, divergence: [], destructive, persistence,
      policy: { file: null, decision: null, violations: [] }, irreversibleAllowed: [], proseConflicts: [], diffAnomaly: null,
      results: [], maxLevel: null, counts: {},
    };
    const field = (): SkillPactFindingField => ({
      contract_path: a.contract.path, contract_version: a.contract.schemaVersion, level: a.level, signed: a.signed, author: a.author,
      declared_effects: a.declared, observed_effects: a.observed, policy_decision: a.policy.decision, l2_tested: a.l2Tested,
      divergence: a.divergence, diff_anomaly: a.diffAnomaly !== null,
    });
    const hits: { level: Severity; path: string; detail: string; ruleId: string; ruleNo: number }[] = [];
    const hit = (ruleNo: number, level: Severity, path: string, detail: string, ruleId: string) => hits.push({ level, path, detail, ruleId, ruleNo });
    const skillPath = dir || '.';
    const c = parse(cfile);
    if (!cfile || c === 'invalid' || c === null) {
      a.contract.parseError = c === 'invalid';
      a.divergence = observedSorted.filter((e) => e !== 'read');
      hit(1, 'HIGH', c === 'invalid' ? cfile!.relPath : skillPath, c === 'invalid' ? 'SkillPact 契約ファイルが JSON オブジェクトとして解析できません（未宣言として扱う）' : 'SkillPact 契約ファイルが存在しません', 's49-undeclared');
    } else {
      const toks = tokens(c);
      a.declaredTokens = toks;
      a.declared = sortEffects(toks.map(baseOf));
      a.contract.schemaVersion = str(c['schema_version']);
      a.contract.supported = sp.schema_versions.includes(a.contract.schemaVersion ?? '');
      a.author = str(c['author'] ?? c['publisher']);
      a.version = str(c['version']);
      a.level = str(c['level']);
      const cdec = str(c['decision'] ?? c['policy_decision']);
      // ポリシー
      const pfile = sp.policy_files.map((p) => inSkill(p) ?? ctx.byPath.get(ctx.root ? `${ctx.root}/${p}` : p)).find(Boolean);
      let pdec = cdec;
      if (pfile) {
        a.policy.file = pfile.relPath;
        const p = parse(pfile);
        if (p && p !== 'invalid') {
          const rules = Array.isArray(p['rules']) ? (p['rules'] as Record<string, unknown>[]) : [];
          const dflt = str(p['default']) ?? 'ask';
          const decide = (t: string) => rules.find((r) => r['effect'] === t || r['effect'] === baseOf(t) || r['effect'] === `${baseOf(t)}:any`)?.['decision'] as string | undefined ?? dflt;
          const rank = (d: string) => (d === 'deny' ? 3 : d === 'ask' ? 2 : d === 'allow' ? 1 : 0);
          if (!pdec) pdec = toks.length ? toks.map(decide).sort((x, y) => rank(y) - rank(x))[0] ?? dflt : dflt;
          const never = Array.isArray(p['never_auto_allow_any']) ? (p['never_auto_allow_any'] as string[]) : sp.risk_flags;
          const covers = (flag: string, t: string) => t === flag || (flag.endsWith(':any') && baseOf(t) === baseOf(flag));
          const explicit = rules.filter((r) => r['decision'] === 'allow').flatMap((r) => never.filter((n) => n === r['effect'] || covers(n, String(r['effect']))));
          const implicit = toks.flatMap((t) => never.filter((n) => covers(n, t) && decide(t) === 'allow'));
          a.policy.violations = [...new Set([...explicit, ...implicit])];
        }
      }
      a.policy.decision = pdec;
      if (!a.policy.violations.length && cdec === 'allow') {
        a.policy.violations = [...new Set(toks.flatMap((t) => sp.risk_flags.filter((rf) => t === rf || (rf.endsWith(':any') && baseOf(t) === baseOf(rf) && (t.split(':')[1] ?? 'any') === 'any'))))];
      }
      // L2
      const l2 = (c['l2'] ?? (c['tests'] as Record<string, unknown> | undefined)?.['l2']) as Record<string, unknown> | undefined;
      const rec = str(l2?.['record'] ?? c['l2_record']);
      const want = str(l2?.['sha256'] ?? c['l2_sha256'])?.replace(/^sha256:/, '') ?? null;
      const recFile = rec ? (rec.startsWith('/') || rec.includes('..') ? undefined : inSkill(rec)) : sp.l2_record_filenames.map(inSkill).find(Boolean);
      a.l2Tested = !!recFile && (!want || recFile.sha256 === want);
      // L3 署名（存在のみ）
      const sig = str((c['signature'] as Record<string, unknown> | undefined)?.['file'] ?? c['signature_file']);
      a.signed = (sig && !sig.startsWith('/') && !sig.includes('..') ? !!inSkill(sig) : false) || sp.signature_filenames.some((s) => !!inSkill(s));
      // 乖離
      a.divergence = observedSorted.filter((e) => e !== 'read' && !a.declared.includes(e));
      if (persistence && !a.declared.includes('persist') && !a.declared.includes('write')) a.divergence = sortEffects([...a.divergence, 'persist']);
      // 差分異常
      if (a.author && c['name'] && a.version) {
        const prev = allContracts
          .filter((x) => x.f !== cfile && str(x.c['author'] ?? x.c['publisher']) === a.author && x.c['name'] === c['name'] && typeof x.c['version'] === 'string' && versionCmp(x.c['version'] as string, a.version!) < 0)
          .sort((x, y) => versionCmp(String(y.c['version']), String(x.c['version'])))[0];
        if (prev) {
          const pt = tokens(prev.c);
          const added = toks.filter((t) => !pt.includes(t));
          const delta = new Set([...added, ...pt.filter((t) => !toks.includes(t))]).size;
          const union = new Set([...toks, ...pt]).size;
          const reasons: string[] = [];
          if (a.declared.includes('exec') && !pt.map(baseOf).includes('exec')) reasons.push('exec 新規追加');
          if (added.some((t) => t.startsWith('network'))) reasons.push('network 送信先の新規追加');
          if (added.some((t) => t.startsWith('secrets'))) reasons.push('secrets スコープ拡大');
          const score = union ? delta / union : 0;
          if (score > threshold) reasons.push(`エフェクト差分率 ${Math.floor(score * 100)}% > 閾値 ${Math.floor(threshold * 100)}%`);
          if (reasons.length) a.diffAnomaly = { previousVersion: String(prev.c['version']), previousPath: prev.f.relPath, reasons, score, threshold };
        }
      }
      const cp = cfile.relPath;
      const sig3 = a.signed ? '（L3 署名済みでも重大度は下げません）' : '';
      if (!a.contract.supported) hit(2, 'MEDIUM', cp, `契約の schema_version が ${a.contract.schemaVersion ?? '未指定'}（対応: ${sp.schema_versions.join(',')}）。互換性不明`, 's49-schema');
      if (a.level && !sp.levels.includes(a.level)) hit(2, 'MEDIUM', cp, '契約の level が L1/L2/L3 以外', 's49-level');
      if (a.level === 'L3' && !a.signed) hit(2, 'MEDIUM', cp, 'L3 を宣言しているが署名ファイルが見つかりません', 's49-l3-nosig');
      if (pdec && !sp.decision_values.includes(pdec)) hit(11, 'MEDIUM', cp, 'ポリシー決定の値が decision_values（allow/ask/deny）外', 's49-decision-value');
      if (a.declared.some((e) => RISKY.includes(e)) && !a.l2Tested) hit(3, 'HIGH', cp, 'exec/network/secrets を宣言しているが L2 テスト記録がありません（宣言のみで検証なし）', 's49-l2');
      (['exec', 'network', 'secrets'] as const).forEach((e, i) => {
        if (a.divergence.includes(e)) hit(4 + i, 'CRITICAL', skillPath, `契約は ${e} を宣言していないが、実態に ${e} を検出${sig3}`, `s49-divergence:${e}`);
      });
      if (a.divergence.includes('spend')) hit(4, 'HIGH', skillPath, `契約は spend を宣言していないが、実態に課金/決済処理を検出${sig3}`, 's49-divergence:spend');
      if (a.divergence.includes('write') && !persistence) hit(8, 'MEDIUM', skillPath, `契約は write を宣言していないが、実態にファイル書き込みを検出${sig3}`, 's49-divergence:write');
      if (destructive && pdec === 'allow') hit(7, 'HIGH', skillPath, '破壊的操作（destructive_markers）を含むスキルが allow（自動許可）', 's49-destructive');
      if (persistence && a.divergence.includes('persist')) hit(8, 'CRITICAL', skillPath, `永続化操作（persistence_markers）を検出したが、契約に persist/write の宣言がありません${sig3}`, 's49-persistence');
      const desc = typeof c['description'] === 'string' ? (c['description'] as string) : '';
      for (const pc of prose) {
        if (!pc.re) continue;
        if (pc.re.test(proseText) || pc.re.test(desc)) {
          const bad = a.declared.filter((e) => pc.forbids.includes(e));
          if (bad.length) {
            a.proseConflicts.push({ claim: pc.claim, sourcePath: cp, contradictedBy: bad });
            hit(9, 'HIGH', cp, `prose（${pc.claim}）と契約が矛盾: 契約が ${bad.join(',')} を宣言`, `s49-prose:${pc.claim}`);
          }
        }
      }
      if (a.diffAnomaly) hit(10, 'HIGH', cp, `${a.signed ? 'L3 署名済みだが' : ''}同一作者の前バージョン ${a.diffAnomaly.previousVersion} から差分異常: ${a.diffAnomaly.reasons.join(' / ')}`, 's49-diff-anomaly');
      if (a.policy.violations.length) {
        hit(11, 'HIGH', a.policy.file ?? cp, a.policy.file ? `ポリシーが never_auto_allow_any を尊重していません（自動許可: ${a.policy.violations.join(',')}）` : `契約の decision: allow が never_auto_allow_any の対象（${a.policy.violations.join(',')}）を自動許可しています`, 's49-never-auto-allow');
      }
      const ops = Array.isArray(c['operations']) ? (c['operations'] as Record<string, unknown>[]) : [];
      for (const op of ops) {
        if (op['reversible'] === false && ((op['decision'] as string | undefined) ?? pdec) === 'allow') {
          const name = String(op['name'] ?? op['id'] ?? 'unnamed');
          a.irreversibleAllowed.push(name);
          hit(12, 'CRITICAL', cp, `reversible: false の操作が allow（不可逆操作の自動許可）`, `s49-irreversible:${name}`);
        }
      }
    }
    // §5.7 検出ルール表 12 行
    const TITLES: [string, Severity][] = [
      ['契約ファイルが存在しない', 'HIGH'], ['schema_version が 0.8 以外', 'MEDIUM'], ['exec/network/secrets 宣言で L2 記録なし', 'HIGH'],
      ['未宣言の exec', 'CRITICAL'], ['未宣言の network', 'CRITICAL'], ['未宣言の secrets', 'CRITICAL'],
      ['破壊的マーカー × allow', 'HIGH'], ['永続化マーカー × persist/write 未宣言', 'CRITICAL'], ['prose と契約の矛盾', 'HIGH'],
      ['L3 でも前版から exec/network 新規追加', 'HIGH'], ['never_auto_allow_any を尊重していない', 'HIGH'], ['reversible:false 操作が allow', 'CRITICAL'],
    ];
    const noContract = !a.contract.found || a.contract.parseError;
    a.results = TITLES.map(([title, level], i): RuleResult => {
      const n = i + 1;
      const isHit = hits.some((h) => h.ruleNo === n && (n !== 4 || h.ruleId === 's49-divergence:exec') && (n !== 8 || h.ruleId === 's49-persistence'));
      let status: RuleResult['status'] = isHit ? 'hit' : 'clear';
      if (!isHit && noContract && n !== 1) status = 'n/a';
      if (!isHit && n === 10 && !noContract && !a.diffAnomaly) status = 'undetermined';
      return { ruleNo: n, title, level, status };
    });
    for (const h of hits) {
      a.counts[h.level] = (a.counts[h.level] ?? 0) + 1;
      if (!a.maxLevel || SEVERITY_RANK[h.level] > SEVERITY_RANK[a.maxLevel]) a.maxLevel = h.level;
      push(ctx, { level: h.level, module: '§49', campaign: h.ruleId === 's49-undeclared' ? 'skillpact-undeclared' : h.ruleId === 's49-diff-anomaly' ? 'skillpact-account-compromise' : 'skillpact-divergence', path: h.path, detail: h.detail, ruleId: h.ruleId, skillpact: field() });
    }
    out.push(a);
  }
  return out;
}

function esc(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

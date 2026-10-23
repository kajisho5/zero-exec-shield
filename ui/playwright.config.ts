import { defineConfig, devices } from '@playwright/test';

// ローカルは環境に導入済みの Chromium（PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers）だけを使う。playwright install はしない。
// CI では E2E_ALL_BROWSERS=1 で Firefox / WebKit（Safari 系エンジン）も実行する（file:// での CSP・クリップボードの差を確認するため）。
const all = process.env['E2E_ALL_BROWSERS'] === '1';
// The existing specs check the Japanese UI, so the default browser locale is ja-JP. tests/e2e/i18n.spec.ts switches to
// en-US (the English UI is the default for every other locale).
const use = { headless: true, viewport: { width: 1440, height: 900 }, locale: 'ja-JP' };

export default defineConfig({
  testDir: 'tests/e2e',
  timeout: 60_000,
  // CI は 3 エンジンを直列に実行し（並列の負荷による停止を切り分けるため）、失敗時の trace を残す
  workers: all ? 1 : undefined,
  use: { ...use, trace: all ? 'retain-on-failure' : 'off' },
  reporter: 'list',
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'], ...use } },
    ...(all ? [
      { name: 'firefox', use: { ...devices['Desktop Firefox'], ...use } },
      { name: 'webkit', use: { ...devices['Desktop Safari'], ...use } },
    ] : []),
  ],
});

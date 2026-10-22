import { defineConfig, devices } from '@playwright/test';

// ローカルは環境に導入済みの Chromium（PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers）だけを使う。playwright install はしない。
// CI では E2E_ALL_BROWSERS=1 で Firefox / WebKit（Safari 系エンジン）も実行する（file:// での CSP・クリップボードの差を確認するため）。
const all = process.env['E2E_ALL_BROWSERS'] === '1';
const use = { headless: true, viewport: { width: 1440, height: 900 } };

export default defineConfig({
  testDir: 'tests/e2e',
  timeout: 60_000,
  use,
  reporter: 'list',
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'], ...use } },
    ...(all ? [
      { name: 'firefox', use: { ...devices['Desktop Firefox'], ...use } },
      { name: 'webkit', use: { ...devices['Desktop Safari'], ...use } },
    ] : []),
  ],
});

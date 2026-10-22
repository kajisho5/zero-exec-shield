import { defineConfig } from '@playwright/test';

// Chromium は環境に導入済みのもの（PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers）を使う。playwright install はしない。
export default defineConfig({
  testDir: 'tests/e2e',
  timeout: 60_000,
  use: { headless: true, viewport: { width: 1440, height: 900 } },
  reporter: 'list',
});

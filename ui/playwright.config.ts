import { defineConfig, devices } from '@playwright/test';

// Locally, only the Chromium already installed in the environment (PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers) is used. No playwright install.
// In CI, E2E_ALL_BROWSERS=1 also runs Firefox / WebKit (the Safari-family engine) (to check the CSP and clipboard differences on file://).
const all = process.env['E2E_ALL_BROWSERS'] === '1';
// The existing specs check the Japanese UI, so the default browser locale is ja-JP. tests/e2e/i18n.spec.ts switches to
// en-US (the English UI is the default for every other locale).
const use = { headless: true, viewport: { width: 1440, height: 900 }, locale: 'ja-JP' };

export default defineConfig({
  testDir: 'tests/e2e',
  timeout: 60_000,
  // CI runs the 3 engines serially (to tell stalls caused by parallel load apart) and keeps traces on failure
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

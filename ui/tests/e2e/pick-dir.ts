import type { Page } from '@playwright/test';

// Playwright Firefox / WebKit occasionally do not return from setInputFiles on a directory.
// It reproduces even on an empty page without any app code (only <input webkitdirectory>), so it is a problem of the automation, not of the UI.
// Each wait is limited to 15 seconds, and if it does not return the same operation is retried (up to 3 times; fails if none of the 3 return).
export async function pickDir(page: Page, dir: string | string[]): Promise<void> {
  let last: unknown;
  for (let i = 0; i < 3; i++) {
    try {
      await page.getByTestId('dir-input').setInputFiles(dir, { timeout: 15_000 });
      return;
    } catch (e) {
      last = e;
    }
  }
  throw last;
}

import type { Page } from '@playwright/test';

// Playwright の Firefox / WebKit は、ディレクトリの setInputFiles がまれに返らないことがある。
// アプリのコードが無い空のページ（<input webkitdirectory> だけ）でも再現するため、UI ではなく自動操作側の問題。
// 1 回の待ちを 15 秒に区切り、返らなければ同じ操作をやり直す（最大 3 回。3 回とも返らなければ失敗させる）。
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

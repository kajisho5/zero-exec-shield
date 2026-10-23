// English UI and the language switch (i18n DESIGN §5.1). The browser locale is en-US here; the other specs run in ja-JP.
import { expect, test, type Page } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { pickDir } from './pick-dir';

const INDEX = 'file://' + fileURLToPath(new URL('../../../index.html', import.meta.url));
const FIX = fileURLToPath(new URL('../../../tests/fixtures/', import.meta.url));

test.use({ locale: 'en-US' });

async function open(page: Page, query = '') {
  const errors: string[] = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(e.message));
  await page.context().route(/^(?!file:|data:|blob:).*/, (r) => r.abort());
  await page.goto(INDEX + query);
  return errors;
}

async function scan(page: Page, fixture: string, done = 'Scan complete') {
  await pickDir(page, FIX + fixture);
  await expect(page.getByTestId('scan-status')).toContainText(done);
}

/** Japanese text anywhere on the page (text, aria-label, placeholder, title). Since 0.5.0 phase B the engine's findings
 *  are catalog messages too, so an English page after a scan has none; only the language menu's endonym 日本語 is
 *  Japanese, and the menu is closed when this runs. */
async function japaneseText(page: Page) {
  return page.evaluate(() => {
    const cjk = /[぀-ヿ㐀-鿿＀-￯]/;
    const out: string[] = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const el = n.parentElement;
      if (!el || el.closest('script,style') || !cjk.test(n.textContent ?? '')) continue;
      out.push((n.textContent ?? '').trim().slice(0, 40));
    }
    for (const el of document.querySelectorAll('[aria-label],[placeholder],[title]')) {
      for (const a of ['aria-label', 'placeholder', 'title']) {
        const v = el.getAttribute(a);
        if (v && cjk.test(v)) out.push(`${a}=${v.slice(0, 40)}`);
      }
    }
    return out;
  });
}

test('English by default for a non-Japanese browser: html[lang], tabs, header, sample record', async ({ page }) => {
  const errors = await open(page);
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page.getByRole('tab', { name: /^Overview/ })).toBeVisible();
  await expect(page.getByRole('banner').getByRole('button', { name: 'Open findings.json' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Drop a folder to scan' })).toBeVisible();
  expect(await japaneseText(page)).toEqual([]);
  await scan(page, 'chaindrop');
  const form = page.getByRole('region', { name: 'Sample record' });
  for (const label of ['Sample', 'Files', 'Scan time', 'Not scanned', 'Executed']) await expect(form).toContainText(label);
  await expect(page.getByTestId('card-SAFE')).toContainText('checks with no match');
  // UI-made findings show the catalog message (f.<code>) in the selected language: no Japanese, no lang="ja" details
  const table = page.getByTestId('findings-table');
  await expect(table).toContainText('ChainDrop preinstall hook (node setup.mjs)');
  await expect(page.getByTestId('finding-row').locator('[lang="ja"]')).toHaveCount(0);
  expect(await japaneseText(page)).toEqual([]);
  // The same findings in Japanese (the CLI's Japanese wording), without scanning again
  await page.getByTestId('lang').click();
  await page.getByRole('menuitemradio', { name: '日本語' }).click();
  await expect(table).toContainText('ChainDrop の preinstall フック（node setup.mjs）');
  await page.getByTestId('lang').click();
  await page.getByRole('menuitemradio', { name: 'English' }).click();
  await expect(table).toContainText('ChainDrop preinstall hook (node setup.mjs)');
  expect(errors).toEqual([]);
});

test('English SkillPact tab: rule names come from the catalog, no Japanese text', async ({ page }) => {
  const errors = await open(page);
  await scan(page, 'skillpact-signed-divergence');
  await page.getByRole('tab', { name: /^SkillPact/ }).click();
  await expect(page.getByTestId('skillpact-viewer')).toBeVisible();
  await expect(page.getByTestId('rule-row').filter({ hasText: 'Undeclared network' })).toHaveAttribute('data-status', 'hit');
  expect(await japaneseText(page)).toEqual([]);
  expect(errors).toEqual([]);
});

test('the language menu switches to Japanese and back; the choice survives a reload', async ({ page }) => {
  await open(page);
  await page.getByTestId('lang').click();
  await expect(page.getByRole('menuitemradio', { name: 'English' })).toHaveAttribute('aria-checked', 'true');
  await expect(page.getByRole('menuitemradio', { name: '日本語' })).toHaveAttribute('lang', 'ja');
  await page.getByRole('menuitemradio', { name: '日本語' }).click();
  await expect(page.locator('html')).toHaveAttribute('lang', 'ja');
  await expect(page.getByRole('tab', { name: /^総合/ })).toBeVisible();
  await expect(page.getByTestId('lang')).toHaveText('JA');
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('lang', 'ja');
  await expect(page.getByRole('heading', { name: 'フォルダをドロップして判定' })).toBeVisible();
  await page.getByTestId('lang').click();
  await page.getByRole('menuitemradio', { name: 'English' }).click();
  await expect(page.getByRole('tab', { name: /^Overview/ })).toBeVisible();
});

test('?lang=ja overrides the browser language; Japanese and English tab names both search', async ({ page }) => {
  await open(page, '?lang=ja');
  await expect(page.locator('html')).toHaveAttribute('lang', 'ja');
  await page.getByTestId('all-tabs').click();
  await page.getByRole('combobox', { name: 'タブを検索' }).fill('persistence');
  await expect(page.getByRole('dialog').getByRole('option')).toHaveText(['永続化']);
  await page.keyboard.press('Escape');
  await page.goto(INDEX + '?lang=en');
  await page.getByTestId('all-tabs').click();
  await page.getByRole('combobox', { name: 'Search tabs' }).fill('永続化');
  await expect(page.getByRole('dialog').getByRole('option')).toHaveText(['Persistence']);
});

test('works when localStorage throws (file:// in some browsers, private mode)', async ({ page }) => {
  await page.addInitScript(() => {
    const fail = () => { throw new DOMException('denied', 'SecurityError'); };
    Storage.prototype.getItem = fail;
    Storage.prototype.setItem = fail;
    Storage.prototype.removeItem = fail;
  });
  const errors = await open(page);
  await expect(page.getByRole('tab', { name: /^Overview/ })).toBeVisible();
  await page.getByTestId('lang').click();
  await page.getByRole('menuitemradio', { name: '日本語' }).click();
  await expect(page.getByRole('tab', { name: /^総合/ })).toBeVisible();
  expect(errors).toEqual([]);
});

test('a Japanese browser gets the Japanese UI', async ({ browser }) => {
  const ctx = await browser.newContext({ locale: 'ja-JP' });
  const page = await ctx.newPage();
  await page.goto(INDEX);
  await expect(page.locator('html')).toHaveAttribute('lang', 'ja');
  await expect(page.getByRole('tab', { name: /^総合/ })).toBeVisible();
  await ctx.close();
});

test('<640: no language button; the "…" menu has the language radio group', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await open(page);
  await expect(page.getByTestId('lang')).toBeHidden();
  await page.getByRole('button', { name: 'More actions' }).click();
  await expect(page.getByTestId('lang-menu')).toBeVisible();
  await page.getByRole('menuitemradio', { name: '日本語' }).click();
  await expect(page.locator('html')).toHaveAttribute('lang', 'ja');
  await page.getByRole('button', { name: 'その他の操作' }).click();
  await expect(page.getByRole('menuitemradio', { name: '日本語' })).toHaveAttribute('aria-checked', 'true');
});

/** Horizontal page overflow and the elements that stick out (outside scroll areas). */
async function overflow(page: Page) {
  return page.evaluate(() => {
    const cw = document.documentElement.clientWidth;
    const clipped = (e: Element) => { for (let p = e.parentElement; p; p = p.parentElement) { if (['auto', 'scroll', 'hidden'].includes(getComputedStyle(p).overflowX)) return true; } return false; };
    const bad = [...document.querySelectorAll('body *')].filter((e) => { const b = e.getBoundingClientRect(); return b.width > 0 && b.right > cw + 1 && !clipped(e); })
      .slice(-3).map((e) => `${e.tagName}.${String(e.className).slice(0, 60)} "${(e.textContent ?? '').slice(0, 30)}"`);
    return { sw: document.documentElement.scrollWidth, cw, bad };
  });
}

for (const lang of ['en', 'ja'] as const) {
  for (const width of [1440, 1280, 1024, 768, 375, 320]) {
    test(`${lang} ${width}px: no page overflow, header on one row, sample record labels on one line`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await open(page, `?lang=${lang}`);
      await scan(page, 'chaindrop', lang === 'en' ? 'Scan complete' : 'スキャン完了');
      const r = await overflow(page);
      expect(r.sw, `${lang} ${width}px: ${r.bad.join(' | ')}`).toBeLessThanOrEqual(r.cw);
      const header = await page.locator('header').boundingBox();
      expect(header!.height).toBeLessThanOrEqual(56);
      // Every field label fits on one line and does not overlap its value
      const labels = await page.getByTestId('dropzone').evaluate((el) => [...el.querySelectorAll('span.whitespace-nowrap')].map((s) => {
        const b = s.getBoundingClientRect();
        const cell = s.parentElement!.getBoundingClientRect();
        return { text: s.textContent, fits: b.right <= cell.right + 0.5 && b.left >= cell.left - 0.5, h: b.height };
      }));
      expect(labels.length).toBe(4);
      for (const l of labels) {
        expect(l.fits, `${l.text} at ${width}px`).toBe(true);
        expect(l.h, `${l.text} wraps at ${width}px`).toBeLessThan(20);
      }
      // The scan status keeps its text on one line (it broke one character per line at 1280 in 0.3.1)
      const status = await page.getByTestId('scan-status').locator('span').first().boundingBox();
      expect(status!.height).toBeLessThan(24);
    });
  }
}

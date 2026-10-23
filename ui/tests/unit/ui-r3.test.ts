// 0.3.1 の UI 修正の単体テスト: 仮想スクロールの範囲（U1）、タブ切り替えでのモジュール絞り込み（U2）、
// 表示用の制御文字の目印（U3）。
import { describe, expect, it } from 'vitest';
import { virtualWindow } from '../../src/lib/virtualWindow';
import { visibleOpt, visiblePath } from '../../src/lib/visiblePath';
import { initialState, reducer } from '../../src/state/reducer';

describe('virtualWindow（U1）', () => {
  it('古い top（行が減った・領域を付け直した直後）でも先頭側の行を描き、空の範囲にしない', () => {
    // 400 行を末尾までスクロールした top のまま、行が 400 → 11 に減った
    const w = virtualWindow(11, 60, 600, 400 * 60 - 600);
    expect(w.start).toBe(0);
    expect(w.end).toBe(11);
    // 400 行に戻り、領域を付け直した（scrollTop は 0）
    const back = virtualWindow(400, 60, 600, 0);
    expect([back.start, back.end]).toEqual([0, 15]);
  });
  it('末尾までスクロールしたときは末尾の行を描く', () => {
    const w = virtualWindow(400, 60, 600, 400 * 60 - 600);
    expect(w.end).toBe(400);
    expect(w.start).toBeLessThan(390);
  });
  it('0 件・負の top でも壊れない', () => {
    expect(virtualWindow(0, 96, 576, 5000)).toEqual({ height: 96, start: 0, end: 0 });
    expect(virtualWindow(3, 96, 576, -10)).toEqual({ height: 288, start: 0, end: 3 });
  });
});

describe('SET_TAB でモジュールの絞り込みを消す（U2）', () => {
  it('別のタブへ移ると moduleFilter は null。同じタブなら保つ', () => {
    const s = reducer(reducer(initialState, { type: 'SET_TAB', tab: 'mcp' }), { type: 'SET_MODULE', module: '§17' });
    expect(reducer(s, { type: 'SET_TAB', tab: 'mcp' }).ui.moduleFilter).toBe('§17');
    expect(reducer(s, { type: 'SET_TAB', tab: 'actions' }).ui.moduleFilter).toBeNull();
  });
});

describe('visiblePath（U3）', () => {
  it('双方向制御文字を ⟨U+XXXX⟩ にする（RLO による拡張子の偽装を見せる）', () => {
    expect(visiblePath('/home/u/invoice\u202Egnp.js')).toBe('/home/u/invoice⟨U+202E⟩gnp.js');
    expect(visiblePath('\u2066a\u2069\u200F\u061C\u200E\u202A\u202B\u202C\u202D\u2067\u2068'))
      .toBe('⟨U+2066⟩a⟨U+2069⟩⟨U+200F⟩⟨U+061C⟩⟨U+200E⟩⟨U+202A⟩⟨U+202B⟩⟨U+202C⟩⟨U+202D⟩⟨U+2067⟩⟨U+2068⟩');
  });
  it('C0・DEL・C1 の制御文字を目印にする', () => {
    expect(visiblePath('a\nb\tc\u0007d\u0000e\u007Ff\u0085g\u009Fh')).toBe('a⟨U+000A⟩b⟨U+0009⟩c⟨U+0007⟩d⟨U+0000⟩e⟨U+007F⟩f⟨U+0085⟩g⟨U+009F⟩h');
  });
  it('普通の文字（日本語・アラビア文字・絵文字・ZWJ）は変えない', () => {
    const s = '/proj/検体/ملف.js/👩‍💻/a b';
    expect(visiblePath(s)).toBe(s);
  });
  it('visibleOpt は null / undefined をそのまま返す', () => {
    expect(visibleOpt(null)).toBeNull();
    expect(visibleOpt(undefined)).toBeUndefined();
    expect(visibleOpt('x\u202E')).toBe('x⟨U+202E⟩');
  });
});

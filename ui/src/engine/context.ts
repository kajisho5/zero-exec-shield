import type { IocDb } from './ioc';
import type { BlastRadiusItem, ExtensionView, FileInput, McpConfigView, ScanError, WorkflowView } from './types';
import type { FindingSpec } from './util';

/** ルール関数に渡す共有コンテキスト。ルールは push で検出を積むだけで、出力の組み立ては index.ts が行う。 */
export interface RuleCtx {
  files: FileInput[];
  byPath: Map<string, FileInput>;
  ioc: IocDb;
  specs: FindingSpec[];
  blast: BlastRadiusItem[];
  viewers: { mcp: McpConfigView[]; actions: WorkflowView[]; extensions: ExtensionView[] };
  errors: ScanError[];
  checks: Set<string>;
  /** 投入フォルダの最上位ディレクトリ（webkitRelativePath の先頭要素。無ければ ''） */
  root: string;
  /** homeLike() の結果（初回呼び出しで決まる） */
  home?: boolean;
}

export function push(ctx: RuleCtx, spec: FindingSpec): void {
  ctx.specs.push(spec);
}

/** 判定に内容を使えるファイル（read のみ）。 */
export function readable(ctx: RuleCtx): (FileInput & { text: string })[] {
  return ctx.files.filter((f): f is FileInput & { text: string } => f.text !== null);
}

export function named(ctx: RuleCtx, re: RegExp): FileInput[] {
  return ctx.files.filter((f) => re.test(f.name));
}

export function pathMatch(ctx: RuleCtx, re: RegExp): (FileInput & { text: string })[] {
  return readable(ctx).filter((f) => re.test(f.relPath));
}

/** ルート直下のパスか（webkitRelativePath は "<top>/<file>" 形式）。 */
export function atRoot(ctx: RuleCtx, f: FileInput): boolean {
  const rest = ctx.root ? f.relPath.slice(ctx.root.length + 1) : f.relPath;
  return !rest.includes('/');
}

/** 投入フォルダの最上位ディレクトリからの相対パス。 */
export function rootRel(ctx: RuleCtx, f: { relPath: string }): string {
  return ctx.root ? f.relPath.slice(ctx.root.length + 1) : f.relPath;
}

/** ~/ 直下のシェル設定ファイル（CLI HOME_RC_FILES と同じ）。 */
export const HOME_RC_FILES = ['.bashrc', '.bash_profile', '.profile', '.zshrc', '.zprofile', '.zshenv', '.zlogin', '.bash_login'];

const HOME_MARKER = /^(Library|\.config|\.local|\.cache|\.ssh)\/|^\.(bash|zsh)_history$/;

/**
 * 投入フォルダが HOME ディレクトリと見なせるか。CLI は ~/ の IoC パスや ~/.npmrc 等を検査対象 HOME（ZES_HOME）でだけ見る。
 * ブラウザには HOME の概念がないため、直下に HOME に特有のエントリ（Library/・.config/・.local/・.cache/・.ssh/・
 * シェル履歴）があるときだけ、投入フォルダを HOME として扱う（リポジトリ直下の .pwd を ~/.pwd と取り違えない）。
 * .bashrc 等のシェル設定は dotfiles リポジトリやホストを模したフォルダにもあるため目印にしない。
 */
export function homeLike(ctx: RuleCtx): boolean {
  if (ctx.home === undefined) ctx.home = ctx.files.some((f) => HOME_MARKER.test(rootRel(ctx, f)));
  return ctx.home;
}

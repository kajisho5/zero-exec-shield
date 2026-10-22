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

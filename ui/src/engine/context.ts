import type { IocDb } from './ioc';
import type { BlastRadiusItem, ExtensionView, FileInput, McpConfigView, ScanError, WorkflowView } from './types';
import type { FindingSpec } from './util';

/** Shared context passed to the rule functions. Rules only push findings; index.ts assembles the output. */
export interface RuleCtx {
  files: FileInput[];
  byPath: Map<string, FileInput>;
  ioc: IocDb;
  specs: FindingSpec[];
  blast: BlastRadiusItem[];
  viewers: { mcp: McpConfigView[]; actions: WorkflowView[]; extensions: ExtensionView[] };
  errors: ScanError[];
  checks: Set<string>;
  /** Top-level directory of the loaded folder (first element of webkitRelativePath; '' if none) */
  root: string;
  /** Files of the root .git that the CLI reads although it prunes $ROOT/.git, .hg and .svn from its inventory:
   *  .git/config (§26) and .git/hooks/* (§7). They are not in files, so no other rule sees them */
  vcs: FileInput[];
  /** Result of homeLike() (fixed on the first call) */
  home?: boolean;
}

export function push(ctx: RuleCtx, spec: FindingSpec): void {
  ctx.specs.push(spec);
}

/** Files whose content may be used for evaluation (read only). */
export function readable(ctx: RuleCtx): (FileInput & { text: string })[] {
  return ctx.files.filter((f): f is FileInput & { text: string } => f.text !== null);
}

export function named(ctx: RuleCtx, re: RegExp): FileInput[] {
  return ctx.files.filter((f) => re.test(f.name));
}

export function pathMatch(ctx: RuleCtx, re: RegExp): (FileInput & { text: string })[] {
  return readable(ctx).filter((f) => re.test(f.relPath));
}

/** Whether the path is directly under the root (webkitRelativePath has the form "<top>/<file>"). */
export function atRoot(ctx: RuleCtx, f: FileInput): boolean {
  const rest = ctx.root ? f.relPath.slice(ctx.root.length + 1) : f.relPath;
  return !rest.includes('/');
}

/** Path relative to the top-level directory of the loaded folder. */
export function rootRel(ctx: RuleCtx, f: { relPath: string }): string {
  return ctx.root ? f.relPath.slice(ctx.root.length + 1) : f.relPath;
}

/** Shell config files directly under ~/ (same as CLI HOME_RC_FILES). */
export const HOME_RC_FILES = ['.bashrc', '.bash_profile', '.profile', '.zshrc', '.zprofile', '.zshenv', '.zlogin', '.bash_login'];

const HOME_MARKER = /^(Library|\.config|\.local|\.cache|\.ssh)\/|^\.(bash|zsh)_history$/;

/**
 * Whether the loaded folder can be regarded as a HOME directory. The CLI looks at ~/ IoC paths, ~/.npmrc etc. only in the inspected HOME (ZES_HOME).
 * The browser has no notion of HOME, so the loaded folder is treated as HOME only when it has entries specific to HOME directly under it (Library/, .config/, .local/, .cache/, .ssh/,
 * shell history) (so a .pwd directly under a repository is not mistaken for ~/.pwd).
 * Shell configs such as .bashrc also appear in dotfiles repositories and in folders imitating a host, so they are not used as markers.
 */
export function homeLike(ctx: RuleCtx): boolean {
  if (ctx.home === undefined) ctx.home = ctx.files.some((f) => HOME_MARKER.test(rootRel(ctx, f)));
  return ctx.home;
}

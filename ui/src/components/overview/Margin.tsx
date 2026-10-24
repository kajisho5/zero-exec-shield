// Side notes (the right column of design doc §10.3). Not cards: notes placed on the bench, separated by rules. No icon before the headings.
// Pasted-text result / Blast Radius / host checks are in the CLI / breakdown of not scanned.
import { useState, type ReactNode } from 'react';
import { CircleDashed, Copy } from 'lucide-react';
import type { BlastRadiusItem } from '@/engine';
import { CLI_COMMAND } from '@/tabs/definitions';
import { useLang, type MsgKey } from '@/i18n';
import { cn } from '@/lib/utils';
import { visiblePath } from '@/lib/visiblePath';
import { Tag } from '@/components/severity/Tag';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { useCopy } from '@/components/ui/toast';
import { Tip } from '@/components/ui/tooltip';

export const PASTE_MAX = 1_000_000;

export function Note({ children, className, ...rest }: { children: ReactNode; className?: string } & React.HTMLAttributes<HTMLElement>) {
  return <section className={cn('flex min-w-0 flex-col', className)} {...rest}>{children}</section>;
}
const H = ({ children }: { children: ReactNode }) => <h2 className="text-[15px] font-semibold">{children}</h2>;

export function PasteCheck({ onPaste, inSheet }: { onPaste(text: string): void; inSheet?: boolean }) {
  const [text, setText] = useState('');
  const { t, fmt } = useLang();
  return (
    <Note aria-label={t('ui.paste.title')} className={inSheet ? 'px-4 pt-3' : undefined}>
      {!inSheet && <H>{t('ui.paste.title')}</H>}
      <p className="text-xs text-muted-foreground">{t('ui.paste.hint')}</p>
      <Textarea
        value={text}
        maxLength={PASTE_MAX}
        onChange={(e) => setText(e.target.value)}
        aria-label={t('ui.paste.aria')}
        data-testid="paste"
        placeholder={`${t('ui.paste.placeholder1')}\n${t('ui.paste.placeholder2')}`}
        className="mt-2.5 h-[84px]"
      />
      <div className="mt-2.5 flex items-center justify-between gap-3">
        <span className="text-xs text-muted-foreground tabular-nums">{t('ui.paste.counter', { n: fmt(text.length), max: fmt(PASTE_MAX) })}</span>
        <Button variant="outline" size="sm" disabled={!text.trim()} onClick={() => { onPaste(text); setText(''); }} data-testid="paste-submit" className="w-[92px]">{t('ui.paste.submit')}</Button>
      </div>
    </Note>
  );
}

export function BlastRadius({ items }: { items: BlastRadiusItem[] }) {
  const copy = useCopy();
  const { lang, t } = useLang();
  const size = (n: number) => (n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`);
  return (
    <Note data-testid="blast-radius">
      <div className="flex flex-wrap items-center gap-2.5"><H>{t('ui.blast.title')}</H><Tag>{t('ui.blast.tag')}</Tag></div>
      <p className="mt-2 text-[12.5px] leading-[1.45] text-muted-foreground">{t('ui.blast.desc')}{lang === 'ja' ? <br /> : ' '}{t('ui.blast.refs')}</p>
      {items.length === 0 ? (
        <div className="mt-3 flex h-11 items-center gap-2.5 rounded-md border border-dashed border-input px-3.5 text-[13px] text-muted-foreground">
          <CircleDashed aria-hidden="true" className="size-4 shrink-0" />{t('ui.blast.none')}
        </div>
      ) : (
        <ul className="mt-3 max-h-[260px] overflow-y-auto border-y border-border">
          {items.map((b) => (
            <li key={b.path} className="flex items-baseline gap-3 border-b border-dotted border-border py-2 last:border-0">
              <bdi dir="ltr" className="min-w-0 flex-1 truncate font-mono text-[13px]" title={visiblePath(b.path)}>{visiblePath(b.path)}</bdi>
              <span className="shrink-0 text-xs text-muted-foreground tabular-nums">{size(b.size)}</span>
            </li>
          ))}
        </ul>
      )}
      <p className="mt-3.5 text-xs text-muted-foreground">{t('ui.blast.count', { n: items.length })}</p>
      {/* English: the steps line does not fit beside the button (225 px vs 196 px), so it gets its own row (i18n mockup) */}
      <div className={cn('mt-2 flex flex-wrap items-start justify-between gap-x-3 gap-y-2', lang === 'en' && 'flex-col')}>
        <p className={cn('text-xs leading-normal text-muted-foreground', lang === 'ja' && 'max-w-[13.5em] min-w-[12.5em] flex-1')}>{t('ui.blast.steps')}</p>
        <Button size="sm" disabled={!items.length} onClick={() => copy(items.map((b) => b.path).join('\n'), t('ui.copy.paths')) /* copy keeps the original values */} className="shrink-0"><Copy />{t('ui.blast.copy')}</Button>
      </div>
    </Note>
  );
}

function Command({ label }: { label?: string }) {
  const copy = useCopy();
  const { t } = useLang();
  return (
    <div className="flex h-10 min-w-0 items-center justify-between gap-2 rounded-md border border-border bg-muted pr-1 pl-3">
      <code className="min-w-0 truncate font-mono text-[13px]">{CLI_COMMAND}</code>
      <Tip label={t('ui.cli.copy')} side="left">
        <Button variant="ghost" size="icon-sm" aria-label={label ?? t('ui.cli.copy')} onClick={() => copy(CLI_COMMAND, t('ui.copy.command'))}><Copy /></Button>
      </Tip>
    </div>
  );
}

export function CliOnlyNotice({ note, compact }: { note?: MsgKey; compact?: boolean }) {
  const { t } = useLang();
  if (compact) {
    return (
      <Note data-testid="cli-only" className="gap-2 border-y border-border py-3 sm:flex-row sm:items-center sm:gap-4">
        <p className="min-w-0 flex-1 text-[13px] text-muted-foreground"><span className="font-semibold text-foreground">{t('ui.cli.compact_prefix')}</span>{note && t(note)}</p>
        <div className="sm:w-[300px]"><Command /></div>
      </Note>
    );
  }
  return (
    <Note data-testid="cli-only">
      <H>{t('ui.cli.title')}</H>
      <p className="mt-2 text-[13px] leading-[1.55] text-muted-foreground">{t(note ?? 'ui.cli.body')}</p>
      <div className="mt-3"><Command /></div>
    </Note>
  );
}

/** Git files that the dropped folder points to but that lie outside it (gitDiscover): the browser cannot read them, so
 *  they are a CLI-only check. Shown only when there are some; the paths are as written in the pointing file */
export function GitOutside({ paths }: { paths: string[] }) {
  const { t } = useLang();
  if (!paths.length) return null;
  return (
    <Note data-testid="git-outside">
      <H>{t('ui.git_outside.title')}</H>
      <p className="mt-2 text-[13px] leading-[1.55] text-muted-foreground">{t('ui.git_outside.body')}</p>
      <ul className="mt-2 max-h-[160px] overflow-y-auto">
        {paths.map((p) => (
          <li key={p} className="border-b border-dotted border-border py-1.5 last:border-0">
            <bdi dir="ltr" className="block min-w-0 truncate font-mono text-[13px]" title={visiblePath(p)}>{visiblePath(p)}</bdi>
          </li>
        ))}
      </ul>
    </Note>
  );
}

export function Undetermined({ skippedSize, skippedBinary, decoys, errors }: { skippedSize: number; skippedBinary: number; decoys: number; errors: number }) {
  const { t } = useLang();
  const rows: [MsgKey, number][] = [['ui.und.size', skippedSize], ['ui.und.binary', skippedBinary], ['ui.und.decoy', decoys], ['ui.und.errors', errors]];
  return (
    <Note data-testid="undetermined">
      <H>{t('ui.und.title')}</H>
      <dl className="mt-1.5">
        {rows.map(([k, v]) => (
          <div key={k} className="flex items-baseline justify-between gap-3 border-b border-dotted border-border py-[7px] text-[13px] last:border-0">
            <dt className="min-w-0">{t(k)}</dt><dd className="font-medium tabular-nums">{v}</dd>
          </div>
        ))}
      </dl>
    </Note>
  );
}

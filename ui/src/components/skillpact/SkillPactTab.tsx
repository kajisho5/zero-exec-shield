// SkillPact tab (experimental. design doc §10.5). Compares the permissions a skill declared (SkillPact 0.8 contract) with what its code is observed to do.
// Left: the skill list on the bench. Right: the report (one sheet divided into sections by rules).
// Not a single SAFE (green) part. A signature is the violet stamp "signed (unverified)"; never write L2 / L3 or "safe".
// Always place a sentence with the meaning next to a stamp (do not hide it in a tooltip).
import { useMemo, useState, type ReactNode } from 'react';
import { CircleDashed, GitCompare, Search } from 'lucide-react';
import { EFFECTS, IOC, type Severity, type SkillPactAnalysis } from '@/engine';
import { t as tNow, textLang, useLang, type MsgKey } from '@/i18n';
import { cn } from '@/lib/utils';
import { visibleOpt, visiblePath } from '@/lib/visiblePath';
import { SEV } from '@/components/severity/severity';
import { SeverityMark } from '@/components/severity/SeverityMark';
import { SeverityTag } from '@/components/severity/SeverityTag';
import { Stamp } from '@/components/severity/Stamp';
import { Tag } from '@/components/severity/Tag';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';

const SPEC = IOC.skillpact.spec;
const ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

/** Contract status (result of the ZES partial checks). L2 / L3 are not evaluated. */
function contractValue(a: SkillPactAnalysis, t: typeof tNow): { text: string; tone?: 'medium' } {
  const s = a.contract.status;
  const v = a.contract.contractVersion ?? '?';
  if (s === 'none') return { text: t('ui.sp.contract.none') };
  if (s === 'unparseable') return { text: t('ui.sp.contract.unparseable'), tone: 'medium' };
  if (s === 'unsupported') return { text: t('ui.sp.contract.unsupported', { v }), tone: 'medium' };
  if (s === 'invalid') return { text: t('ui.sp.contract.invalid', { v }), tone: 'medium' };
  return { text: t('ui.sp.contract.ok', { v }) };
}

export function SignedStamp({ signed, size }: { signed: boolean; size?: 'sm' | 'md' }) {
  const { t } = useLang();
  if (!signed) return null;
  return <Stamp size={size} data-testid="signed-badge" title={t('ui.sp.signed_title')}>{t('ui.sp.signed')}</Stamp>;
}

function Counts({ a, className }: { a: SkillPactAnalysis; className?: string }) {
  return (
    <span className={cn('flex flex-wrap gap-1.5', className)}>
      {ORDER.map((s) => (a.counts[s] ? <SeverityTag key={s} level={s}>{s} {a.counts[s]}</SeverityTag> : null))}
    </span>
  );
}

function SkillList({ skills, selected, onSelect }: { skills: SkillPactAnalysis[]; selected: string | null; onSelect(id: string): void }) {
  const [q, setQ] = useState('');
  const { t } = useLang();
  const shown = useMemo(() => {
    const n = q.normalize('NFKC').toLowerCase().trim();
    return n ? skills.filter((s) => `${s.name} ${s.skillId}`.normalize('NFKC').toLowerCase().includes(n)) : skills;
  }, [q, skills]);
  return (
    <div className="flex min-w-0 flex-col">
      <h2 className="flex items-baseline gap-2 text-base font-semibold">{t('ui.sp.skills')}<span className="text-[13px] font-normal text-muted-foreground tabular-nums">{t('ui.sp.skills_count', { n: skills.length })}</span></h2>
      <p className="mt-0.5 text-xs text-muted-foreground">{t('ui.sp.unit')}</p>
      {skills.length >= 5 && <Input icon={<Search aria-hidden="true" className="size-4 shrink-0" />} value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('ui.sp.filter')} aria-label={t('ui.sp.filter')} className="mt-3" />}
      <ul className="mt-3 flex flex-col gap-2" aria-label={t('ui.sp.list')}>
        {shown.map((s) => {
          const sel = s.skillId === selected;
          return (
            <li key={s.skillId}>
              <button type="button" aria-pressed={sel} onClick={() => onSelect(s.skillId)} data-testid="skill-item"
                className={cn('relative w-full overflow-hidden rounded-md border px-4 py-3 text-left', sel ? 'border-border bg-card' : 'border-transparent hover:bg-accent')}>
                {sel && <span aria-hidden="true" className="absolute inset-y-0 left-0 w-[3px] bg-foreground" />}
                <span className="block truncate text-sm font-semibold" title={visiblePath(s.name)}>{visiblePath(s.name)}</span>
                <bdi dir="ltr" className="block truncate font-mono text-xs text-muted-foreground">{visiblePath(s.skillId)}/</bdi>
                <span className="mt-2 flex flex-wrap items-center gap-2">
                  <SignedStamp signed={s.signed} size="sm" />
                  <Counts a={s} />
                  {!s.maxLevel && <span className="text-xs text-muted-foreground">{t('ui.sp.no_findings')}</span>}
                </span>
              </button>
            </li>
          );
        })}
      </ul>
      <div className="mt-4 rounded-md border border-dashed border-input p-4">
        <div className="flex items-center gap-2 text-[13.5px] font-semibold"><GitCompare aria-hidden="true" className="size-4" />{t('ui.sp.diff_title')}</div>
        <p className="mt-2 text-xs leading-relaxed text-muted-foreground">{t('ui.sp.diff_body')}</p>
      </div>
      <p className="mt-6 text-xs text-muted-foreground">{t('ui.sp.no_safe')}</p>
      <p className="mt-1.5 text-xs text-muted-foreground"><a className="underline underline-offset-2" href={SPEC.url} target="_blank" rel="noreferrer">SkillPact</a> {t('ui.sp.license')}</p>
    </div>
  );
}

function Fact({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-0.5">
      <dt className="text-xs text-muted-foreground">{k}</dt>
      <dd className="text-sm font-medium wrap-anywhere">{children}</dd>
    </div>
  );
}

function Section({ children, className }: { children: ReactNode; className?: string }) {
  return <section className={cn('min-w-0 border-t border-border px-7 py-6 max-sm:px-4', className)}>{children}</section>;
}

function EffectMatrix({ a }: { a: SkillPactAnalysis }) {
  const compared = a.contract.status === 'ok' || a.contract.status === 'invalid';
  const { t } = useLang();
  const cell = 'border border-border px-2 text-center';
  return (
    <Section>
      <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2">
        <h3 className="text-[15px] font-semibold">{t('ui.sp.effects_title')}</h3>
        <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
          <span className="flex items-center gap-1.5"><span className="size-3 rounded-xs bg-critical-solid" />{t('ui.sp.undeclared')}</span>
          <span className="flex items-center gap-1.5"><span className="size-3 rounded-xs border-[1.5px] border-foreground" />{t('ui.sp.declared')}</span>
          <span>{t('ui.sp.none')}</span>
        </div>
      </div>
      {/* The effects columns do not fit a narrow width, so only the table scrolls horizontally (the page as a whole never scrolls horizontally) */}
      <div className="mt-4 overflow-x-auto">
        <table className="w-full min-w-[640px] table-fixed border-collapse text-[13px]">
          <thead>
            <tr className="h-8 bg-muted text-xs text-muted-foreground">
              <th className={cn(cell, 'w-40 pl-3 text-left font-medium')}>{t('ui.sp.col.kind')}</th>
              {EFFECTS.map((e) => <th key={e} className={cn(cell, 'font-mono text-[12.5px] font-medium')}>{e}</th>)}
            </tr>
          </thead>
          <tbody>
            <tr className="h-10">
              <th scope="row" className={cn(cell, 'pl-3 text-left font-medium')}>{t('ui.sp.col.declared')}</th>
              {EFFECTS.map((e) => (
                <td key={e} className={cell}>
                  {!compared ? <span className="text-muted-foreground">?</span>
                    : a.declared.includes(e) ? <span className="inline-flex h-6 items-center rounded-sm border-[1.5px] border-foreground px-2.5 font-mono text-[12.5px] font-medium">{e}</span>
                      : <span className="text-muted-foreground">—</span>}
                </td>
              ))}
            </tr>
            <tr className="h-10">
              <th scope="row" className={cn(cell, 'pl-3 text-left font-medium')}>{t('ui.sp.col.observed')}</th>
              {EFFECTS.map((e) => {
                const d = a.divergence.find((x) => x.effect === e);
                return (
                  <td key={e} className={cell} data-effect={e} data-divergence={d ? 'true' : 'false'}>
                    {a.observed.includes(e)
                      ? d ? <span className={cn('inline-flex h-6 items-center rounded-sm px-2.5 font-mono text-[12.5px] font-medium', SEV[d.level].solid)}>{e}</span>
                        : <span className="font-mono text-[12.5px] font-medium">{e}</span>
                      : <span className="text-muted-foreground">—</span>}
                  </td>
                );
              })}
            </tr>
            <tr className="h-10">
              <th scope="row" className={cn(cell, 'pl-3 text-left font-medium')}>{t('ui.sp.col.diff')}</th>
              {EFFECTS.map((e) => {
                const d = a.divergence.find((x) => x.effect === e);
                return (
                  <td key={e} className={cn(cell, 'text-xs')}>
                    {d ? <span className={cn('inline-flex items-center gap-1 font-semibold', SEV[d.level].fg)}><SevIcon level={d.level} />{t('ui.sp.diff_cell', { level: d.level })}</span>
                      : a.observed.includes(e) && a.declared.includes(e) ? <span className="text-muted-foreground">{t('ui.sp.match')}</span> : <span className="text-muted-foreground">—</span>}
                  </td>
                );
              })}
            </tr>
          </tbody>
        </table>
      </div>
      <p className="mt-3 text-xs leading-relaxed text-muted-foreground">{t('ui.sp.effects_note')}</p>
    </Section>
  );
}

const RESULT: Record<SkillPactAnalysis['results'][number]['status'], MsgKey> = { hit: 'ui.sp.result.hit', clear: 'ui.sp.result.clear', 'n/a': 'ui.sp.result.na', undetermined: 'ui.sp.result.undetermined' };

function SevIcon({ level }: { level: Severity }) {
  const Icon = SEV[level].icon;
  return <Icon aria-hidden="true" strokeWidth={2.25} className="size-[13px] shrink-0" />;
}

/** A finding row (the same gutter band as the findings list). Inconclusive uses a dashed band and pencil color (no reassurance by color). */
function Remark({ level, title, children, testid }: { level: Severity | null; title: string; children: ReactNode; testid?: string }) {
  const { t } = useLang();
  return (
    <div data-testid={testid} className="relative min-w-0 pl-4">
      {level ? <span aria-hidden="true" className={cn('absolute inset-y-0 left-0 w-1', SEV[level].bar)} />
        : <span aria-hidden="true" className="absolute inset-y-0 left-0 w-0 border-l-[3px] border-dashed border-input" />}
      <h3 className="flex flex-wrap items-center gap-x-3 gap-y-1">
        {level ? <SeverityMark level={level} /> : <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-muted-foreground"><CircleDashed aria-hidden="true" className="size-[13px]" />{t('ui.sp.inconclusive')}</span>}
        <span lang={textLang(title)} className="text-sm font-semibold">{title}</span>
      </h3>
      <div className="mt-1.5 text-[12.5px] leading-relaxed break-words">{children}</div>
    </div>
  );
}

function Report({ a }: { a: SkillPactAnalysis }) {
  const hits = a.results.filter((r) => r.status === 'hit').length;
  const und = a.results.filter((r) => r.status === 'undetermined').length;
  const { t } = useLang();
  const ident = a.diffAnomaly ? t(({ same: 'ui.sp.author.same', changed: 'ui.sp.author.changed', unsigned: 'ui.sp.author.unsigned' } as const)[a.diffAnomaly.identity]) : '';
  const compareUndetermined = !a.diffAnomaly && a.results.some((r) => r.ruleNo === 9 && r.status === 'undetermined');
  const contract = contractValue(a, t);
  return (
    <Card data-testid="skillpact-viewer" className="min-w-0">
      <div className="px-7 pt-6 pb-6 max-sm:px-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <h2 className="text-[22px] leading-[1.35] font-semibold break-words">{visiblePath(a.skillName ?? a.name)}</h2>
            <p className="mt-1 font-mono text-[12.5px] text-muted-foreground wrap-anywhere"><bdi dir="ltr">{visiblePath(a.contract.path ?? `${a.skillId}/`)}</bdi>{a.contract.path ? '' : t('ui.sp.no_contract')}</p>
          </div>
          <Counts a={a} />
        </div>
        <dl className="mt-5 flex flex-wrap gap-x-10 gap-y-3">
          <Fact k="author">{visibleOpt(a.author) ?? '—'}</Fact>
          <Fact k="version">{visibleOpt(a.skillVersion) ?? '—'}</Fact>
          <Fact k={t('ui.sp.fact.sigfile')}>{t(a.signed ? 'ui.sp.fact.sig_yes' : 'ui.sp.fact.sig_no')}</Fact>
          <Fact k={t('ui.sp.fact.contract')}>{contract.tone ? <Tag className="border-0 bg-medium-tint text-medium">{contract.text}</Tag> : contract.text}</Fact>
          <Fact k={t('ui.sp.fact.verdict')}>{a.level ? t('ui.sp.fact.l1') : '—'}</Fact>
          {a.signers.length > 0 && <Fact k={t('ui.sp.fact.signer')}>{visiblePath(a.signers.join(', '))}</Fact>}
        </dl>
        {a.contract.errors.length > 0 && <p className="mt-3 text-xs break-words text-medium">{t('ui.sp.failed')}<span className="font-mono">{a.contract.errors.join(', ')}</span></p>}
        {a.contract.problem && <p className="mt-3 text-xs break-words text-medium">{t('ui.sp.json_problem')}<span lang={textLang(a.contract.problem)}>{a.contract.problem}</span></p>}
        <div className="mt-5 flex flex-wrap items-start gap-x-4 gap-y-2">
          <SignedStamp signed={a.signed} />
          <div className="min-w-0 flex-1 basis-80" data-testid="level-note">
            <p className="text-[13px] font-medium">{t('ui.sp.level_note')}</p>
            <p className="mt-0.5 text-xs text-muted-foreground">{t('ui.sp.experimental')}</p>
          </div>
        </div>
      </div>
      <EffectMatrix a={a} />
      {(a.diffAnomaly || compareUndetermined) && (
        <Section>
          {a.diffAnomaly ? (
            <Remark level={a.diffAnomaly.level} title={t('ui.sp.widened')} testid="diff-alert">
              <p>{t('ui.sp.widened_line', { prev: a.diffAnomaly.previousVersion, cur: a.skillVersion ?? '', changes: a.diffAnomaly.widened.join(' / ') })}</p>
              <p>{t('ui.sp.author_key', { ident })}</p>
              <p className="mt-1 text-xs text-muted-foreground">{t('ui.sp.widened_body')}</p>
            </Remark>
          ) : (
            <Remark level={null} title={t('ui.sp.diff_anomaly')}>
              <p>{t('ui.sp.no_prev')}</p>
              <p className="text-xs text-muted-foreground">{t('ui.sp.signed_warn')}</p>
            </Remark>
          )}
        </Section>
      )}
      <Section>
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <h3 className="text-[15px] font-semibold">{t('ui.sp.rules')}</h3>
          <span className="text-[12.5px] text-muted-foreground">{t('ui.sp.rules_summary', { n: a.results.length, hit: hits, clear: a.results.length - hits - und, und })}</span>
        </div>
        <ol className="mt-3 grid grid-cols-1 gap-x-10 gap-y-1 xl:grid-cols-2">
          {a.results.map((r) => {
            const hit = r.status === 'hit';
            return (
              <li key={r.ruleNo} data-testid="rule-row" data-status={r.status}
                className={cn('relative grid min-h-8 grid-cols-[22px_minmax(0,1fr)_auto_56px] items-center gap-x-2.5 rounded-sm px-2.5 py-1 text-[13px]', hit && SEV[r.level].tint)}>
                {hit && <span aria-hidden="true" className={cn('absolute inset-y-0 left-0 w-[3px]', SEV[r.level].bar)} />}
                <span className="text-right text-[12.5px] font-medium text-muted-foreground tabular-nums">{r.ruleNo}</span>
                <span className="min-w-0 break-words">{t(r.title)}</span>
                <span className={cn('text-xs font-medium', hit ? SEV[r.level].fg : 'text-muted-foreground')}>{r.level}</span>
                <span className={cn('text-right text-[12.5px]', hit ? cn('font-semibold', SEV[r.level].fg) : 'text-muted-foreground')}>{t(RESULT[r.status])}</span>
              </li>
            );
          })}
        </ol>
      </Section>
    </Card>
  );
}

export function SkillPactTab({ skills, selected, onSelect }: { skills: SkillPactAnalysis[]; selected: string | null; onSelect(id: string): void }) {
  const a = skills.find((s) => s.skillId === selected) ?? skills[0];
  const { lang, t } = useLang();
  if (!a) {
    return (
      <div className="flex flex-col gap-4">
        <div className="flex items-center justify-center gap-2 rounded-md border border-dashed border-input px-6 py-12 text-center text-sm text-muted-foreground">
          <CircleDashed aria-hidden="true" className="size-4 shrink-0" />{t('ui.sp.empty')}
        </div>
        <p className="text-xs text-muted-foreground" data-testid="level-note">{t('ui.sp.empty_note')}{lang === 'en' && ' '}{t('ui.sp.level_note')}</p>
      </div>
    );
  }
  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-[296px_minmax(0,1fr)]">
      <SkillList skills={skills} selected={a.skillId} onSelect={onSelect} />
      <Report a={a} />
    </div>
  );
}

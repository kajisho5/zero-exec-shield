// SkillPact タブ（実験的。設計書 §10.5）。スキルが宣言した権限（SkillPact 0.8 契約）とコードの実態を比べる。
// 左: 作業台の上のスキル一覧。右: 報告（台紙 1 枚を罫で節に分ける）。
// SAFE（緑）の部品を一つも置かない。署名は紫印の「署名あり（未検証）」で、L2 / L3 や「安全」とは書かない。
// 押印の隣には必ず意味の文を置く（ツールチップに隠さない）。
import { useMemo, useState, type ReactNode } from 'react';
import { CircleDashed, GitCompare, Search } from 'lucide-react';
import { EFFECTS, IOC, type Severity, type SkillPactAnalysis } from '@/engine';
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
const LEVEL_NOTE = 'ZES は署名の検証・テストの実行を行わないため、L2 / L3 は判定しません。L3 であっても「安全」を意味しません。';
const ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

/** 契約の状態（ZES の部分検査の結果）。L2 / L3 は判定しない。 */
function contractValue(a: SkillPactAnalysis): { text: string; tone?: 'medium' } {
  const s = a.contract.status;
  if (s === 'none') return { text: 'なし（比較対象外）' };
  if (s === 'unparseable') return { text: 'JSON 不正', tone: 'medium' };
  if (s === 'unsupported') return { text: `未対応の版（${a.contract.contractVersion ?? '?'}）`, tone: 'medium' };
  if (s === 'invalid') return { text: `検証できない（v${a.contract.contractVersion ?? '?'}）`, tone: 'medium' };
  return { text: `あり（v${a.contract.contractVersion ?? '?'}）` };
}

export function SignedStamp({ signed, size }: { signed: boolean; size?: 'sm' | 'md' }) {
  if (!signed) return null;
  return <Stamp size={size} data-testid="signed-badge" title="integrity.signatures があります。ZES は署名を検証しません。署名の有無で重大度は変えません。">署名あり（未検証）</Stamp>;
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
  const shown = useMemo(() => {
    const n = q.normalize('NFKC').toLowerCase().trim();
    return n ? skills.filter((s) => `${s.name} ${s.skillId}`.normalize('NFKC').toLowerCase().includes(n)) : skills;
  }, [q, skills]);
  return (
    <div className="flex min-w-0 flex-col">
      <h2 className="flex items-baseline gap-2 text-base font-semibold">スキル<span className="text-[13px] font-normal text-muted-foreground tabular-nums">{skills.length} 件</span></h2>
      <p className="mt-0.5 text-xs text-muted-foreground">SKILL.md / 契約ファイルを含むディレクトリ単位</p>
      {skills.length >= 5 && <Input icon={<Search aria-hidden="true" className="size-4 shrink-0" />} value={q} onChange={(e) => setQ(e.target.value)} placeholder="スキル名・パスで絞り込み" aria-label="スキル名・パスで絞り込み" className="mt-3" />}
      <ul className="mt-3 flex flex-col gap-2" aria-label="スキル一覧">
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
                  {!s.maxLevel && <span className="text-xs text-muted-foreground">検出なし（静的解析の範囲内）</span>}
                </span>
              </button>
            </li>
          );
        })}
      </ul>
      <div className="mt-4 rounded-md border border-dashed border-input p-4">
        <div className="flex items-center gap-2 text-[13.5px] font-semibold"><GitCompare aria-hidden="true" className="size-4" />前版との差分比較</div>
        <p className="mt-2 text-xs leading-relaxed text-muted-foreground">同じスキルの前版の契約を一緒に投入すると、major を上げない権限拡大（SkillPact §17）を検出します。ブラウザはレジストリを取得しません。</p>
      </div>
      <p className="mt-6 text-xs text-muted-foreground">SAFE 表示は使用しません（安全の断定をしない）</p>
      <p className="mt-1.5 text-xs text-muted-foreground"><a className="underline underline-offset-2" href={SPEC.url} target="_blank" rel="noreferrer">SkillPact</a> © SEVENTHWELL (shogo kajiyama)、仕様 CC BY 4.0</p>
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
  const cell = 'border border-border px-2 text-center';
  return (
    <Section>
      <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2">
        <h3 className="text-[15px] font-semibold">エフェクト：宣言（契約） vs 実態（静的解析）</h3>
        <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
          <span className="flex items-center gap-1.5"><span className="size-3 rounded-xs bg-critical-solid" />未宣言（乖離）</span>
          <span className="flex items-center gap-1.5"><span className="size-3 rounded-xs border-[1.5px] border-foreground" />宣言あり</span>
          <span>— なし</span>
        </div>
      </div>
      {/* エフェクトの列は狭い幅に収まらないので、表だけを横スクロールさせる（ページ全体は横にスクロールさせない） */}
      <div className="mt-4 overflow-x-auto">
        <table className="w-full min-w-[640px] table-fixed border-collapse text-[13px]">
          <thead>
            <tr className="h-8 bg-muted text-xs text-muted-foreground">
              <th className={cn(cell, 'w-40 pl-3 text-left font-medium')}>区分</th>
              {EFFECTS.map((e) => <th key={e} className={cn(cell, 'font-mono text-[12.5px] font-medium')}>{e}</th>)}
            </tr>
          </thead>
          <tbody>
            <tr className="h-10">
              <th scope="row" className={cn(cell, 'pl-3 text-left font-medium')}>宣言（契約）</th>
              {EFFECTS.map((e) => (
                <td key={e} className={cell}>
                  {!compared ? <span className="text-muted-foreground">?</span>
                    : a.declared.includes(e) ? <span className="inline-flex h-6 items-center rounded-sm border-[1.5px] border-foreground px-2.5 font-mono text-[12.5px] font-medium">{e}</span>
                      : <span className="text-muted-foreground">—</span>}
                </td>
              ))}
            </tr>
            <tr className="h-10">
              <th scope="row" className={cn(cell, 'pl-3 text-left font-medium')}>実態（静的解析）</th>
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
              <th scope="row" className={cn(cell, 'pl-3 text-left font-medium')}>差分</th>
              {EFFECTS.map((e) => {
                const d = a.divergence.find((x) => x.effect === e);
                return (
                  <td key={e} className={cn(cell, 'text-xs')}>
                    {d ? <span className={cn('inline-flex items-center gap-1 font-semibold', SEV[d.level].fg)}><SevIcon level={d.level} />未宣言・{d.level}</span>
                      : a.observed.includes(e) && a.declared.includes(e) ? <span className="text-muted-foreground">一致</span> : <span className="text-muted-foreground">—</span>}
                  </td>
                );
              })}
            </tr>
          </tbody>
        </table>
      </div>
      <p className="mt-3 text-xs leading-relaxed text-muted-foreground">read は機密ファイル（~/.ssh、.env、認証情報など）を読む兆候のみ、write は作業領域外への永続的な書き込み（crontab、.bashrc など）を含みます。宣言は permissions.*.level が none 以外のもの。</p>
    </Section>
  );
}

function SevIcon({ level }: { level: Severity }) {
  const Icon = SEV[level].icon;
  return <Icon aria-hidden="true" strokeWidth={2.25} className="size-[13px] shrink-0" />;
}

/** 指摘の行（検出一覧と同じ溝の帯）。判定不可は破線の帯と鉛筆色（色で安心させない）。 */
function Remark({ level, title, children, testid }: { level: Severity | null; title: string; children: ReactNode; testid?: string }) {
  return (
    <div data-testid={testid} className="relative min-w-0 pl-4">
      {level ? <span aria-hidden="true" className={cn('absolute inset-y-0 left-0 w-1', SEV[level].bar)} />
        : <span aria-hidden="true" className="absolute inset-y-0 left-0 w-0 border-l-[3px] border-dashed border-input" />}
      <h3 className="flex flex-wrap items-center gap-x-3 gap-y-1">
        {level ? <SeverityMark level={level} /> : <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-muted-foreground"><CircleDashed aria-hidden="true" className="size-[13px]" />判定不可</span>}
        <span className="text-sm font-semibold">{title}</span>
      </h3>
      <div className="mt-1.5 text-[12.5px] leading-relaxed break-words">{children}</div>
    </div>
  );
}

function Report({ a }: { a: SkillPactAnalysis }) {
  const hits = a.results.filter((r) => r.status === 'hit').length;
  const und = a.results.filter((r) => r.status === 'undetermined').length;
  const ident = a.diffAnomaly ? { same: '前版と同一（未検証）', changed: '前版と異なる（未検証）', unsigned: '署名なし' }[a.diffAnomaly.identity] : '';
  const compareUndetermined = !a.diffAnomaly && a.results.some((r) => r.ruleNo === 9 && r.status === 'undetermined');
  const contract = contractValue(a);
  return (
    <Card data-testid="skillpact-viewer" className="min-w-0">
      <div className="px-7 pt-6 pb-6 max-sm:px-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <h2 className="text-[22px] leading-[1.35] font-semibold break-words">{visiblePath(a.skillName ?? a.name)}</h2>
            <p className="mt-1 font-mono text-[12.5px] text-muted-foreground wrap-anywhere"><bdi dir="ltr">{visiblePath(a.contract.path ?? `${a.skillId}/`)}</bdi>{a.contract.path ? '' : '（skill.contract.json なし）'}</p>
          </div>
          <Counts a={a} />
        </div>
        <dl className="mt-5 flex flex-wrap gap-x-10 gap-y-3">
          <Fact k="author">{visibleOpt(a.author) ?? '—'}</Fact>
          <Fact k="version">{visibleOpt(a.skillVersion) ?? '—'}</Fact>
          <Fact k="署名ファイル">{a.signed ? 'あり（検証は未実行）' : 'なし'}</Fact>
          <Fact k="契約">{contract.tone ? <Tag className="border-0 bg-medium-tint text-medium">{contract.text}</Tag> : contract.text}</Fact>
          <Fact k="ZES の判定">{a.level ? 'L1 相当（部分検査）' : '—'}</Fact>
          {a.signers.length > 0 && <Fact k="署名者（自己申告）">{visiblePath(a.signers.join(', '))}</Fact>}
        </dl>
        {a.contract.errors.length > 0 && <p className="mt-3 text-xs break-words text-medium">ZES の部分検査で不合格: <span className="font-mono">{a.contract.errors.join(', ')}</span></p>}
        {a.contract.problem && <p className="mt-3 text-xs break-words text-medium">JSON の問題: {a.contract.problem}</p>}
        <div className="mt-5 flex flex-wrap items-start gap-x-4 gap-y-2">
          <SignedStamp signed={a.signed} />
          <div className="min-w-0 flex-1 basis-80" data-testid="level-note">
            <p className="text-[13px] font-medium">{LEVEL_NOTE}</p>
            <p className="mt-0.5 text-xs text-muted-foreground">実験的。契約は JSON パースのみ。スキル・L2 テスト・署名検証は実行しません。</p>
          </div>
        </div>
      </div>
      <EffectMatrix a={a} />
      {(a.diffAnomaly || compareUndetermined) && (
        <Section>
          {a.diffAnomaly ? (
            <Remark level={a.diffAnomaly.level} title="前版から major を上げずに権限拡大" testid="diff-alert">
              <p>{a.diffAnomaly.previousVersion} → {a.skillVersion}：{a.diffAnomaly.widened.join(' / ')}</p>
              <p>作者署名鍵: {ident}</p>
              <p className="mt-1 text-xs text-muted-foreground">SkillPact §17: 権限を広げるときは major を上げ、利用者に再確認を求めるべきです。署名済みでも警告します（署名は信頼の根拠にしない）。</p>
            </Remark>
          ) : (
            <Remark level={null} title="差分異常">
              <p>前版の契約が投入されていないため比較できません</p>
              <p className="text-xs text-muted-foreground">署名があっても、前版から権限が増えていれば警告します</p>
            </Remark>
          )}
        </Section>
      )}
      <Section>
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <h3 className="text-[15px] font-semibold">§49 検出ルール</h3>
          <span className="text-[12.5px] text-muted-foreground">{a.results.length} ルール：該当 {hits}、非該当・対象外 {a.results.length - hits - und}、判定不可 {und}</span>
        </div>
        <ol className="mt-3 grid grid-cols-1 gap-x-10 gap-y-1 xl:grid-cols-2">
          {a.results.map((r) => {
            const hit = r.status === 'hit';
            return (
              <li key={r.ruleNo} data-testid="rule-row" data-status={r.status}
                className={cn('relative grid min-h-8 grid-cols-[22px_minmax(0,1fr)_auto_56px] items-center gap-x-2.5 rounded-sm px-2.5 py-1 text-[13px]', hit && SEV[r.level].tint)}>
                {hit && <span aria-hidden="true" className={cn('absolute inset-y-0 left-0 w-[3px]', SEV[r.level].bar)} />}
                <span className="text-right text-[12.5px] font-medium text-muted-foreground tabular-nums">{r.ruleNo}</span>
                <span className="min-w-0 break-words">{r.title}</span>
                <span className={cn('text-xs font-medium', hit ? SEV[r.level].fg : 'text-muted-foreground')}>{r.level}</span>
                <span className={cn('text-right text-[12.5px]', hit ? cn('font-semibold', SEV[r.level].fg) : 'text-muted-foreground')}>{{ hit: '該当', clear: '非該当', 'n/a': '対象外', undetermined: '判定不可' }[r.status]}</span>
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
  if (!a) {
    return (
      <div className="flex flex-col gap-4">
        <div className="flex items-center justify-center gap-2 rounded-md border border-dashed border-input px-6 py-12 text-center text-sm text-muted-foreground">
          <CircleDashed aria-hidden="true" className="size-4 shrink-0" />スキル（SKILL.md / skill.contract.json）が見つかりません。スキルのフォルダを投入してください。
        </div>
        <p className="text-xs text-muted-foreground" data-testid="level-note">実験的: AI エージェントのスキルが宣言した権限（SkillPact 契約 skill.contract.json）と、コードが実際にしていること（静的解析）が一致するかを確かめます。{LEVEL_NOTE}</p>
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

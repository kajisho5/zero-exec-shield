// SkillPact タブ（実験的）。スキルが宣言した権限（SkillPact 0.8 契約）とコードの実態を比べる。
// SAFE（緑）表示を使わない。署名は「署名あり（未検証）」と表記し、L2/L3 や「安全」とは書かない。
import { EFFECTS, IOC, type SkillPactAnalysis } from '../engine';
import { Card, Icon, Pill, SEV_STYLE } from './ui';

const SPEC = IOC.skillpact.spec;
const LEVEL_NOTE = 'ZES は署名の検証・テストの実行を行わないため、L2 / L3 は判定しません。L3 であっても「安全」を意味しません。';

export function LevelBadge({ a }: { a: SkillPactAnalysis }) {
  const s = a.contract.status;
  if (s === 'none') return <Pill tone="muted">契約なし（比較対象外）</Pill>;
  if (s === 'unparseable') return <Pill tone="medium">JSON 不正</Pill>;
  if (s === 'unsupported') return <Pill tone="medium">未対応の版 {a.contract.contractVersion ?? '?'}</Pill>;
  if (s === 'invalid') return <Pill tone="medium">検証できない契約</Pill>;
  return <span title={LEVEL_NOTE}><Pill tone="muted">L1 相当（ZES の部分検査）</Pill></span>;
}

export function SignedBadge({ signed }: { signed: boolean }) {
  if (!signed) return null;
  return (
    <span data-testid="signed-badge" title="integrity.signatures があります。ZES は署名を検証しません。署名の有無で重大度は変えません。">
      <Pill tone="signed"><Icon name="seal" size={12} />署名あり（未検証）</Pill>
    </span>
  );
}

function Counts({ a }: { a: SkillPactAnalysis }) {
  return (
    <span className="flex shrink-0 gap-1.5">
      {(['CRITICAL', 'HIGH', 'MEDIUM', 'INFO'] as const).map((s) => (a.counts[s] ? <span key={s} className={`whitespace-nowrap rounded px-1.5 text-xs ${SEV_STYLE[s].fg} ${SEV_STYLE[s].bg}`}>{s} {a.counts[s]}</span> : null))}
    </span>
  );
}

export function SkillList({ skills, selected, onSelect }: { skills: SkillPactAnalysis[]; selected: string | null; onSelect(id: string): void }) {
  return (
    <Card className="flex flex-col p-4">
      <div className="flex items-baseline gap-2"><h2 className="text-lg font-semibold">スキル</h2><span className="text-xs text-subtle">{skills.length}</span></div>
      <p className="text-xs text-subtle">SKILL.md / skill.contract.json を含むディレクトリ単位</p>
      <ul className="mt-3 flex flex-col gap-1" aria-label="スキル一覧">
        {skills.map((s) => {
          const sel = s.skillId === selected;
          return (
            <li key={s.skillId}>
              <button type="button" aria-pressed={sel} onClick={() => onSelect(s.skillId)} data-testid="skill-item"
                className={`w-full rounded-xl border px-4 py-3 text-left ${sel ? 'border-accent bg-surface-2' : 'border-transparent hover:bg-surface-2'}`}>
                <div className="flex items-center justify-between gap-2"><span className="min-w-0 truncate font-semibold" title={s.name}>{s.name}</span><Counts a={s} /></div>
                <div className="truncate font-mono text-xs text-subtle">{s.skillId}/</div>
                <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-muted">
                  <LevelBadge a={s} /><SignedBadge signed={s.signed} />
                  {!s.maxLevel && <span className="flex min-w-0 items-center gap-1 truncate"><Icon name="info" size={12} />検出なし（静的解析の範囲内）</span>}
                </div>
              </button>
            </li>
          );
        })}
      </ul>
      <div className="mt-4 rounded-xl border border-border p-3 text-xs text-subtle">
        <div className="mb-1 flex items-center gap-1.5 font-semibold text-text"><Icon name="diff" size={14} className="text-accent" />前版との比較</div>
        同じスキルの前版の契約を一緒に投入すると、major を上げない権限拡大（SkillPact §17）を検出します。ブラウザはレジストリを取得しません。
      </div>
      <p className="mt-auto pt-4 text-xs text-subtle">SAFE 表示は使用しません（安全の断定をしない）</p>
    </Card>
  );
}

function EffectMatrix({ a }: { a: SkillPactAnalysis }) {
  const compared = a.contract.status === 'ok' || a.contract.status === 'invalid';
  return (
    <Card className="p-5">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold">効果：宣言（契約） vs 実態（静的解析）</h3>
        <div className="flex items-center gap-3 text-xs text-muted">
          <span className="flex items-center gap-1"><span className="h-3 w-3 rounded-sm border border-dashed border-critical" />未宣言（乖離）</span>
          <span className="flex items-center gap-1"><span className="h-3 w-3 rounded-sm border border-accent" />宣言あり</span>
          <span>— なし</span>
        </div>
      </div>
      <table className="mt-3 w-full table-fixed text-sm">
        <thead><tr className="border-b border-border text-xs text-muted"><th className="w-28 py-2 text-left font-normal">区分</th>{EFFECTS.map((e) => <th key={e} className="py-2 font-mono font-normal">{e}</th>)}</tr></thead>
        <tbody>
          <tr><td className="py-2">宣言（契約）</td>{EFFECTS.map((e) => (
            <td key={e} className="text-center">{!compared ? <span className="text-subtle">?</span> : a.declared.includes(e) ? <Pill tone="accent">{e}</Pill> : <span className="text-subtle">—</span>}</td>
          ))}</tr>
          <tr><td className="py-2">実態（静的解析）</td>{EFFECTS.map((e) => {
            const div = a.divergence.some((d) => d.effect === e);
            return (
              <td key={e} className="text-center" data-effect={e} data-divergence={div ? 'true' : 'false'}>
                {a.observed.includes(e) ? (div ? <span className="rounded-full bg-critical px-3 py-0.5 font-mono text-xs font-semibold text-white">{e}</span> : <Pill tone="muted">{e}</Pill>) : <span className="text-subtle">—</span>}
              </td>
            );
          })}</tr>
          <tr><td className="py-2">差分</td>{EFFECTS.map((e) => {
            const d = a.divergence.find((x) => x.effect === e);
            return (
              <td key={e} className="text-center text-xs">
                {d ? <span className="inline-flex items-center gap-1 rounded border border-dashed border-critical px-2 py-0.5 text-critical"><Icon name="high" size={10} />未宣言・{d.level}</span>
                  : a.observed.includes(e) && a.declared.includes(e) ? <span className="text-subtle">一致</span> : <span className="text-subtle">—</span>}
              </td>
            );
          })}</tr>
        </tbody>
      </table>
      <p className="mt-2 text-xs text-subtle">read は機密ファイル（~/.ssh・.env・認証情報など）を読む兆候のみ、write は作業領域外への永続的な書き込み（crontab・.bashrc など）を含みます。宣言は permissions.*.level が none 以外のもの。</p>
    </Card>
  );
}

function Alert({ title, level, children, testid }: { title: string; level: string; children: React.ReactNode; testid: string }) {
  return (
    <div className="relative rounded-xl border border-high bg-surface p-4" data-testid={testid}>
      <div className="flex items-center justify-between"><h3 className="flex items-center gap-2 font-semibold"><Icon name="warn" className="text-high" />{title}</h3><span className="rounded border border-high bg-high-bg px-2 text-xs text-high">{level}</span></div>
      <div className="mt-2 text-sm">{children}</div>
    </div>
  );
}

export function SkillPactViewer({ a }: { a: SkillPactAnalysis }) {
  const hits = a.results.filter((r) => r.status === 'hit').length;
  const und = a.results.filter((r) => r.status === 'undetermined').length;
  const ident = a.diffAnomaly ? { same: '前版と同一（未検証）', changed: '前版と異なる（未検証）', unsigned: '署名なし' }[a.diffAnomaly.identity] : '';
  return (
    <div className="flex flex-col gap-4" data-testid="skillpact-viewer">
      <Card className="p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-baseline gap-3"><h2 className="text-xl font-semibold">{a.skillName ?? a.name}</h2><span className="truncate font-mono text-xs text-muted">{a.contract.path ?? `${a.skillId}/（skill.contract.json なし）`}</span></div>
            <p className="mt-1 text-xs text-subtle">version {a.skillVersion ?? '—'} ・ contract_version {a.contract.contractVersion ?? '—'}{a.signers.length ? ` ・ 署名者（自己申告）: ${a.signers.join(', ')}` : ''}</p>
            {a.contract.errors.length > 0 && <p className="text-xs text-medium">ZES の部分検査で不合格: <span className="font-mono">{a.contract.errors.join(', ')}</span></p>}
            {a.contract.problem && <p className="text-xs text-medium">JSON の問題: {a.contract.problem}</p>}
          </div>
          <div className="flex flex-col items-end gap-2">
            <div className="flex flex-wrap justify-end gap-2"><LevelBadge a={a} /><SignedBadge signed={a.signed} /></div>
            <Counts a={a} />
          </div>
        </div>
      </Card>
      <EffectMatrix a={a} />
      {a.diffAnomaly && (
        <Alert title="前版から major を上げずに権限拡大" level={a.diffAnomaly.level} testid="diff-alert">
          <p>{a.diffAnomaly.previousVersion} → {a.skillVersion}：{a.diffAnomaly.widened.join(' / ')}</p>
          <p>作者署名鍵: {ident}</p>
          <p className="mt-2 text-xs text-subtle">SkillPact §17: 権限を広げるときは major を上げ、利用者に再確認を求めるべきです。署名済みでも警告します（署名は信頼の根拠にしない）。</p>
        </Alert>
      )}
      <Card className="p-5">
        <div className="flex items-baseline gap-3"><h3 className="font-semibold">§49 検出ルール</h3><span className="text-xs text-subtle">{a.results.length} ルール・該当 {hits}・非該当/対象外 {a.results.length - hits - und}・判定不可 {und}</span></div>
        <ol className="mt-3 grid grid-cols-2 gap-x-6">
          {a.results.map((r) => (
            <li key={r.ruleNo} data-testid="rule-row" data-status={r.status} className={`grid grid-cols-[28px_1fr_80px_64px] items-center rounded-md px-2 py-2 text-sm ${r.status === 'hit' ? 'bg-high-bg' : ''}`}>
              <span className="font-mono text-xs text-subtle">{String(r.ruleNo).padStart(2, '0')}</span>
              <span>{r.title}</span>
              <span className="text-xs text-muted">{r.level}</span>
              <span className={`text-right text-xs ${r.status === 'hit' ? 'font-semibold text-high' : 'text-subtle'}`}>{{ hit: '該当', clear: '非該当', 'n/a': '対象外', undetermined: '判定不可' }[r.status]}</span>
            </li>
          ))}
        </ol>
      </Card>
    </div>
  );
}

export function SkillPactTab({ skills, selected, onSelect }: { skills: SkillPactAnalysis[]; selected: string | null; onSelect(id: string): void }) {
  const a = skills.find((s) => s.skillId === selected) ?? skills[0];
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1 rounded-xl border border-signed bg-signed-bg px-4 py-2 text-sm" data-testid="level-note">
        <span className="flex items-center gap-2"><Icon name="info" className="text-signed" /><span><b>実験的</b>: AI エージェントのスキルが宣言した権限（<a className="underline" href={SPEC.url} target="_blank" rel="noreferrer">SkillPact</a> 契約 skill.contract.json）と、コードが実際にしていること（静的解析）が一致するかを確かめます。</span></span>
        <span className="text-xs text-muted">{LEVEL_NOTE} 契約は JSON として読むのみで、スキル・テストは実行しません。SkillPact © SEVENTHWELL (shogo kajiyama)、仕様 CC BY 4.0。</span>
      </div>
      {skills.length === 0 ? (
        <Card className="p-10 text-center text-sm text-subtle">スキル（SKILL.md / skill.contract.json）が見つかりません。スキルのフォルダを投入してください。</Card>
      ) : (
        <div className="grid grid-cols-[320px_1fr] gap-4">
          <SkillList skills={skills} selected={a?.skillId ?? null} onSelect={onSelect} />
          {a && <SkillPactViewer a={a} />}
        </div>
      )}
    </div>
  );
}

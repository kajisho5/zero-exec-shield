// SkillPact タブ（ui-skillpact.svg）。SAFE（緑）表示を使わない。L3 は「署名済みファイル」と表記し「安全」と書かない。
import { EFFECTS, IOC, type SkillPactAnalysis } from '../engine';
import { Card, Icon, Pill, SEV_STYLE } from './ui';

const L3_NOTE = `L3 は「署名済みファイル」であることのみを示し、安全性や作者の信頼性を意味しません（trust_model.l3_does_not_mean: ${IOC.skillpact.trust_model.l3_does_not_mean}）。`;

export function LevelBadge({ level, signed }: { level: string | null; signed: boolean }) {
  if (level === 'L3') {
    return (
      <span data-testid="l3-badge" title={L3_NOTE}>
        <Pill tone="signed"><Icon name="seal" size={12} />L3 署名済みファイル{signed ? '' : '（署名ファイルなし）'}</Pill>
      </span>
    );
  }
  return <Pill tone="muted">{level ?? 'level 未宣言'}</Pill>;
}

export function PolicyBadge({ decision }: { decision: string | null }) {
  if (!decision) return <Pill tone="muted">ポリシー: なし</Pill>;
  const tone = decision === 'allow' ? 'high' : decision === 'deny' ? 'low' : 'medium';
  return <span title="自動許可（allow）ほど注意"><Pill tone={tone}>ポリシー: {decision}</Pill></span>;
}

function Counts({ a }: { a: SkillPactAnalysis }) {
  return (
    <span className="flex shrink-0 gap-1.5">
      {(['CRITICAL', 'HIGH', 'MEDIUM'] as const).map((s) => (a.counts[s] ? <span key={s} className={`whitespace-nowrap rounded px-1.5 text-xs ${SEV_STYLE[s].fg} ${SEV_STYLE[s].bg}`}>{s} {a.counts[s]}</span> : null))}
    </span>
  );
}

export function SkillList({ skills, selected, onSelect }: { skills: SkillPactAnalysis[]; selected: string | null; onSelect(id: string): void }) {
  return (
    <Card className="flex flex-col p-4">
      <div className="flex items-baseline gap-2"><h2 className="text-lg font-semibold">スキル</h2><span className="text-xs text-subtle">{skills.length}</span></div>
      <p className="text-xs text-subtle">SKILL.md / 契約ファイルを含むディレクトリ単位</p>
      <ul className="mt-3 flex flex-col gap-1" aria-label="スキル一覧">
        {skills.map((s) => {
          const sel = s.skillId === selected;
          return (
            <li key={s.skillId}>
              <button type="button" aria-pressed={sel} onClick={() => onSelect(s.skillId)} data-testid="skill-item"
                className={`w-full rounded-xl border px-4 py-3 text-left ${sel ? 'border-accent bg-surface-2' : 'border-transparent hover:bg-surface-2'}`}>
                <div className="flex items-center justify-between gap-2"><span className="min-w-0 truncate font-semibold" title={s.name}>{s.name}</span><Counts a={s} /></div>
                <div className="truncate font-mono text-xs text-subtle">{s.skillId}/</div>
                <div className="mt-1.5 flex items-center gap-2 text-xs text-muted">
                  {!s.contract.found ? <Pill tone="high">契約なし</Pill> : s.contract.parseError ? <Pill tone="high">JSON 不正</Pill> : <LevelBadge level={s.level} signed={s.signed} />}
                  {!s.maxLevel && <span className="flex min-w-0 items-center gap-1 truncate"><Icon name="info" size={12} />検出なし（静的解析の範囲内）</span>}
                </div>
              </button>
            </li>
          );
        })}
      </ul>
      <div className="mt-4 rounded-xl border border-border p-3 text-xs text-subtle">
        <div className="mb-1 flex items-center gap-1.5 font-semibold text-text"><Icon name="diff" size={14} className="text-accent" />前版との差分比較</div>
        同一作者の前版契約を一緒に投入すると差分異常を比較します。ブラウザはレジストリを取得しません。
      </div>
      <p className="mt-auto pt-4 text-xs text-subtle">SAFE 表示は使用しません（安全の断定をしない）</p>
    </Card>
  );
}

function EffectMatrix({ a }: { a: SkillPactAnalysis }) {
  return (
    <Card className="p-5">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold">エフェクト：宣言（契約） vs 実態（静的解析）</h3>
        <div className="flex items-center gap-3 text-xs text-muted">
          <span className="flex items-center gap-1"><span className="h-3 w-3 rounded-sm border border-dashed border-critical" />未宣言（乖離）</span>
          <span className="flex items-center gap-1"><span className="h-3 w-3 rounded-sm border border-accent" />宣言あり</span>
          <span>— なし</span>
        </div>
      </div>
      <table className="mt-3 w-full table-fixed text-sm">
        <thead><tr className="border-b border-border text-xs text-muted"><th className="w-28 py-2 text-left font-normal">区分</th>{EFFECTS.map((e) => <th key={e} className="py-2 font-mono font-normal">{e}</th>)}</tr></thead>
        <tbody>
          <tr><td className="py-2">宣言（契約）</td>{EFFECTS.map((e) => {
            const tok = a.declaredTokens.find((t) => t.split(':')[0] === e);
            return <td key={e} className="text-center">{tok ? <Pill tone="accent">{tok.length > 18 ? e : tok}</Pill> : <span className="text-subtle">—</span>}</td>;
          })}</tr>
          <tr><td className="py-2">実態（静的解析）</td>{EFFECTS.map((e) => {
            const div = a.divergence.includes(e);
            return (
              <td key={e} className="text-center" data-effect={e} data-divergence={div ? 'true' : 'false'}>
                {a.observed.includes(e) ? (div ? <span className="rounded-full bg-critical px-3 py-0.5 font-mono text-xs font-semibold text-white">{e}</span> : <Pill tone="muted">{e}</Pill>) : <span className="text-subtle">—</span>}
              </td>
            );
          })}</tr>
          <tr><td className="py-2">差分</td>{EFFECTS.map((e) => (
            <td key={e} className="text-center text-xs">
              {a.divergence.includes(e) ? <span className="inline-flex items-center gap-1 rounded border border-dashed border-critical px-2 py-0.5 text-critical"><Icon name="high" size={10} />未宣言・{['exec', 'network', 'secrets'].includes(e) ? 'CRITICAL' : e === 'spend' ? 'HIGH' : 'MEDIUM'}</span> : a.observed.includes(e) && a.declared.includes(e) ? <span className="text-subtle">一致</span> : <span className="text-subtle">—</span>}
            </td>
          ))}</tr>
        </tbody>
      </table>
      {a.divergence.includes('persist') && <p className="mt-2 text-xs text-critical" data-divergence="true">永続化操作を検出したが、契約に persist / write の宣言がありません（CRITICAL）</p>}
    </Card>
  );
}

function Alert({ title, level, children, testid }: { title: string; level: 'HIGH'; children: React.ReactNode; testid: string }) {
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
  return (
    <div className="flex flex-col gap-4" data-testid="skillpact-viewer">
      <Card className="p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-baseline gap-3"><h2 className="text-xl font-semibold">{a.name}</h2><span className="truncate font-mono text-xs text-muted">{a.contract.path ?? `${a.skillId}/（契約ファイルなし）`}</span></div>
            <p className="mt-1 text-xs text-subtle">author: {a.author ?? '—'} ・ version {a.version ?? '—'}{a.diffAnomaly ? ` ・ 前版 ${a.diffAnomaly.previousVersion}（同時投入）` : ''}</p>
            <p className="text-xs text-subtle">L2 記録: {a.l2Tested ? 'あり（存在と SHA-256 を確認）' : 'なし'} ・ 署名ファイル: {a.signed ? 'あり（検証は未実行）' : 'なし'}</p>
          </div>
          <div className="flex flex-col items-end gap-2">
            <div className="flex flex-wrap justify-end gap-2">
              {a.contract.found ? <Pill tone={a.contract.parseError ? 'high' : a.contract.supported ? 'muted' : 'medium'}><Icon name="doc" size={12} />{a.contract.parseError ? 'JSON 不正' : `契約あり・v${a.contract.schemaVersion ?? '?'}`}</Pill> : <Pill tone="high">契約なし</Pill>}
              {a.level && <LevelBadge level={a.level} signed={a.signed} />}
              <PolicyBadge decision={a.policy.decision} />
            </div>
            <Counts a={a} />
          </div>
        </div>
      </Card>
      <EffectMatrix a={a} />
      {(a.proseConflicts.length > 0 || a.diffAnomaly) && (
        <div className="grid grid-cols-2 gap-4">
          {a.proseConflicts.length > 0 ? (
            <Alert title="prose と契約の矛盾" level="HIGH" testid="prose-alert">
              {a.proseConflicts.map((p) => <p key={p.claim}>SKILL.md 等に「{p.claim}」系の記述 → 契約の宣言 <span className="font-mono text-high">{p.contradictedBy.join(', ')}</span> と矛盾</p>)}
              <p className="mt-2 text-xs text-subtle">判定根拠はフレーズ種別のみ表示（本文は表示しません）</p>
            </Alert>
          ) : <div />}
          {a.diffAnomaly ? (
            <Alert title="差分異常（アカウント侵害の疑い）" level="HIGH" testid="diff-alert">
              <p>同一作者 {a.author} ・ {a.diffAnomaly.previousVersion} → {a.version}：{a.diffAnomaly.reasons.join(' / ')}</p>
              <p>スコア {a.diffAnomaly.score.toFixed(2)} ・ 閾値 {a.diffAnomaly.threshold.toFixed(2)}</p>
              <p className="mt-2 text-xs text-subtle">L3 署名済みファイルでも警告します（署名は信頼の根拠にしない）</p>
            </Alert>
          ) : <div />}
        </div>
      )}
      <Card className="p-5">
        <div className="flex items-baseline gap-3"><h3 className="font-semibold">§49 検出ルール</h3><span className="text-xs text-subtle">12 ルール・該当 {hits}・非該当/対象外 {12 - hits - und}・判定不可 {und}</span></div>
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
      <div className="flex items-center justify-between rounded-xl border border-signed bg-signed-bg px-4 py-2 text-sm" data-testid="l3-note">
        <span className="flex items-center gap-2"><Icon name="seal" className="text-signed" />L3 は「署名済みファイル」であることのみを示し、安全性や作者の信頼性を意味しません（trust_model.l3_does_not_mean）。</span>
        <span className="text-xs text-muted">契約は JSON パースのみ・スキル / L2 テスト / 署名検証は実行しません</span>
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

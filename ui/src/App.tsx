import { useMemo } from 'react';
import { analyzeFiles, analyzePaste, IOC, type Finding } from './engine';
import { ImportError, parseFindingsDoc, toFindingsDoc } from './engine/export';
import { fromDataTransfer, fromFileList, readFiles, type PickedFile } from './fileReader';
import { Header, TabBar } from './components/layout';
import { BlastRadiusPanel, CliOnlyNotice, FindingsTable, FindingsToolbar, InputArea, SummaryCards, UndeterminedCard } from './components/overview';
import { SkillPactTab } from './components/skillpact';
import { ErrorBoundary, Icon, useToast } from './components/ui';
import { ActionsViewer, ExtensionViewer, McpViewer } from './components/viewers';
import { ScanProvider, useScan } from './state/ScanContext';
import { allFindings } from './state/reducer';
import { TABS, findingsForTab } from './tabs/definitions';

const nowIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

function Scanner() {
  const { state, dispatch } = useScan();
  const toast = useToast();
  const findings = allFindings(state);
  const tab = TABS.find((t) => t.id === state.ui.activeTab) ?? TABS[0]!;
  const busy = state.phase === 'reading' || state.phase === 'analyzing';

  const scan = async (picked: PickedFile[]) => {
    if (!picked.length) {
      // 何も起きないと「安全」と誤認させるため、0 件であることを必ず知らせる（隠しファイルを渡さないブラウザがある）
      toast({ tone: 'error', text: 'ファイルが 0 件でした。隠しファイル（.mcp.json 等）だけのフォルダはブラウザによって渡されません。ドラッグ＆ドロップか CLI で確認してください' });
      return;
    }
    const t0 = performance.now();
    dispatch({ type: 'SCAN_START', total: picked.length, startedAt: nowIso() });
    try {
      const files = await readFiles(picked, (n) => dispatch({ type: 'SCAN_PROGRESS', processed: n }));
      dispatch({ type: 'SCAN_PROGRESS', processed: picked.length, phase: 'analyzing' });
      const result = await analyzeFiles(files);
      dispatch({ type: 'SCAN_RESULT', result, finishedAt: nowIso(), durationMs: performance.now() - t0 });
    } catch (e) {
      dispatch({ type: 'SCAN_FAIL', message: e instanceof Error ? e.message : String(e) });
      toast({ tone: 'error', text: '判定中にエラーが発生しました（結果は表示しません）' });
    }
  };

  const visible = useMemo(() => {
    const q = state.ui.query.trim().toLowerCase();
    return findingsForTab(tab, findings).filter((f: Finding) =>
      state.ui.severityFilter.has(f.level) && (!state.ui.moduleFilter || f.module === state.ui.moduleFilter)
      && (!q || String(f.path ?? '').toLowerCase().includes(q) || String(f.campaign ?? '').toLowerCase().includes(q)));
  }, [tab, findings, state.ui]);

  const exportJson = () => {
    const doc = toFindingsDoc(findings, state.result?.errors ?? [], IOC.incident_bundle, state.startedAt ?? nowIso(), state.finishedAt ?? nowIso(), state.imported);
    const url = URL.createObjectURL(new Blob([JSON.stringify(doc, null, 2) + '\n'], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = 'findings.json';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  };

  const importJson = async (file: File) => {
    try {
      const doc = parseFindingsDoc(await file.text());
      dispatch({ type: 'IMPORT_FINDINGS', doc });
      if (doc.dropped) toast({ tone: 'error', text: `CLI の findings.json を読み込みました（スキーマに適合しない ${doc.dropped} 件を除外）` });
      else toast({ tone: 'ok', text: 'CLI の findings.json を読み込みました' });
    } catch (e) {
      toast({ tone: 'error', text: e instanceof ImportError ? e.message : 'findings.json を読み込めませんでした' });
    }
  };

  const r = state.result;
  // SAFE = 実行したチェックのうち、1 件も該当しなかったもの（ブラウザ判定範囲のみ）
  const hitChecks = new Set((r?.findings ?? []).map((f) => f.ruleId.split(':')[0]!));
  const total = r?.checksRun.length ?? 0;
  const clear = r ? r.checksRun.filter((c) => !hitChecks.has(c)).length : 0;
  const empty = state.phase === 'idle' ? 'フォルダを投入するか、テキストを貼り付けてください' : findings.length ? '条件に一致する検出はありません' : '検出なし（ブラウザで判定できる範囲内。ホスト検査は CLI で実施）';

  return (
    <div className="min-h-full">
      <Header onExport={exportJson} onClear={() => dispatch({ type: 'CLEAR' })} canExport={findings.length > 0 || !!r} />
      <TabBar active={tab.id} findings={findings} onSelect={(id) => dispatch({ type: 'SET_TAB', tab: id })} />
      <main id={`panel-${tab.id}`} role="tabpanel" aria-labelledby={`tab-${tab.id}`} className="px-8 py-6">
        <ErrorBoundary onReset={() => dispatch({ type: 'CLEAR' })}>
        {tab.id === 'skillpact' ? (
          <SkillPactTab skills={r?.skillpact ?? []} selected={state.ui.selectedSkillId} onSelect={(id) => dispatch({ type: 'SELECT_SKILL', id })} />
        ) : (
          <div className="grid grid-cols-[minmax(0,1fr)_448px] gap-6 max-[1100px]:grid-cols-1">
            <div className="flex min-w-0 flex-col gap-4">
              {tab.id === 'overview' && (
                <InputArea
                  busy={busy}
                  onDrop={async (dt) => scan(await fromDataTransfer(dt))}
                  onPick={(list) => scan(fromFileList(list))}
                  onPaste={async (text) => { dispatch({ type: 'PASTE_RESULT', findings: await analyzePaste(text) }); toast({ tone: 'ok', text: '貼り付けテキストを判定しました（内容は保持しません）' }); }}
                  onImport={importJson}
                />
              )}
              <div className="flex flex-wrap items-center gap-4 text-sm" aria-live="polite" data-testid="scan-status">
                {busy && <span className="text-muted">{state.phase === 'reading' ? '読み取り中' : '判定中'} … {state.progress.processed.toLocaleString()} / {state.progress.total.toLocaleString()} ファイル</span>}
                {state.phase === 'done' && r && (
                  <span className="flex items-center gap-1.5 text-muted"><Icon name="safe" size={14} className="text-safe" />スキャン完了 ・ {r.stats.files.toLocaleString()} ファイル ・ {(state.durationMs / 1000).toFixed(1)} 秒</span>
                )}
                {r && <span className="text-xs text-subtle">未判定 {r.stats.skippedSize + r.stats.skippedBinary + r.stats.zeroByteDecoys + r.stats.errors} 件（サイズ超過 {r.stats.skippedSize} / バイナリ {r.stats.skippedBinary} / リンク先不明 {r.stats.zeroByteDecoys}）→ 右パネル参照</span>}
                {state.imported && <span className="text-xs text-accent" data-testid="import-status">CLI 取り込み: {state.imported.findings.length} 件（status: {state.imported.status}）{state.imported.dropped > 0 && <span className="ml-1 text-high">・スキーマ不適合で除外 {state.imported.dropped} 件</span>}</span>}
                {state.phase === 'error' && <span className="text-critical">エラー: {state.errorMessage}</span>}
              </div>
              {tab.cliOnlyNote && <CliOnlyNotice note={tab.cliOnlyNote} compact />}
              <SummaryCards findings={findingsForTab(tab, findings)} active={state.ui.severityFilter} safe={{ clear, total }} onToggle={(s) => dispatch({ type: 'TOGGLE_SEVERITY', severity: s })} />
              <FindingsToolbar findings={findingsForTab(tab, findings)} active={state.ui.severityFilter} onToggle={(s) => dispatch({ type: 'TOGGLE_SEVERITY', severity: s })}
                query={state.ui.query} onQuery={(q) => dispatch({ type: 'SET_QUERY', query: q })} module={state.ui.moduleFilter} onModule={(m) => dispatch({ type: 'SET_MODULE', module: m })} />
              <FindingsTable findings={visible} empty={empty} />
              {tab.viewer === 'mcp' && <McpViewer configs={r?.viewers.mcp ?? []} />}
              {tab.viewer === 'actions' && <ActionsViewer workflows={r?.viewers.actions ?? []} />}
              {tab.viewer === 'extensions' && <ExtensionViewer manifests={r?.viewers.extensions ?? []} />}
            </div>
            <aside className="flex flex-col gap-4">
              <BlastRadiusPanel items={r?.blastRadius ?? []} />
              <CliOnlyNotice />
              <UndeterminedCard skippedSize={r?.stats.skippedSize ?? 0} skippedBinary={r?.stats.skippedBinary ?? 0} decoys={r?.stats.zeroByteDecoys ?? 0} errors={r?.stats.errors ?? 0} />
            </aside>
          </div>
        )}
        </ErrorBoundary>
      </main>
    </div>
  );
}

export function App() {
  return (
    <ScanProvider>
      <Scanner />
    </ScanProvider>
  );
}

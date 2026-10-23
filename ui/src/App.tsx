import { useEffect, useMemo, useRef, useState } from 'react';
import { ClipboardPaste, FolderOpen } from 'lucide-react';
import { analyzeFiles, analyzePaste, IOC, SEVERITIES, type Finding, type Severity } from './engine';
import { ImportError, parseFindingsDoc, toFindingsDoc } from './engine/export';
import { fromDataTransfer, fromFileList, readFiles, type PickedFile } from './fileReader';
import { Header } from './components/layout/Header';
import { TabBar } from './components/layout/TabBar';
import { tabCounts } from './components/layout/tabCounts';
import { FindingList, FindingsTable } from './components/overview/Findings';
import { BlastRadius, CliOnlyNotice, PasteCheck, Undetermined } from './components/overview/Margin';
import { Intake, SpecimenForm, type SpecimenStatus } from './components/overview/SpecimenForm';
import { Tally } from './components/overview/Tally';
import { SkillPactTab } from './components/skillpact/SkillPactTab';
import { ErrorBoundary } from './components/ui/alert';
import { Button } from './components/ui/button';
import { Sheet, SheetContent } from './components/ui/sheet';
import { Tabs, TabsContent } from './components/ui/tabs';
import { useToast } from './components/ui/toast';
import { ActionsViewer, ExtensionViewer, McpViewer } from './components/viewers/Viewers';
import { useIsMobile } from './hooks/useMediaQuery';
import { ScanProvider, useScan } from './state/ScanContext';
import { allFindings } from './state/reducer';
import { TABS, findingsForTab, type TabId } from './tabs/definitions';

const nowIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

/** 検体名: 投入したフォルダの最上位の名前（webkitRelativePath の先頭）。 */
const specimenOf = (picked: PickedFile[]) => {
  const p = picked[0]?.relPath ?? '';
  const i = p.indexOf('/');
  return i > 0 ? p.slice(0, i + 1) : p || 'フォルダ';
};

function Scanner() {
  const { state, dispatch } = useScan();
  const toast = useToast();
  const mobile = useIsMobile();
  const findings = allFindings(state);
  const tab = TABS.find((t) => t.id === state.ui.activeTab) ?? TABS[0]!;
  const busy = state.phase === 'reading' || state.phase === 'analyzing';
  const [specimen, setSpecimen] = useState<string | null>(null);
  const [pasteOpen, setPasteOpen] = useState(false);
  // 貼り付けシートを閉じたらフォーカスを開いたボタンへ戻す。開く前（未投入）と後（投入済み）でボタンが入れ替わるので、
  // 押したボタンが消えていれば、いま出ている方（data-paste-opener）へ戻す
  const pasteOpener = useRef<HTMLElement | null>(null);
  const openPaste = (e: React.MouseEvent<HTMLElement>) => { pasteOpener.current = e.currentTarget; setPasteOpen(true); };
  const returnPasteFocus = (e: Event) => {
    const el = pasteOpener.current?.isConnected ? pasteOpener.current : document.querySelector<HTMLElement>('[data-paste-opener]');
    if (el) { e.preventDefault(); el.focus(); }
  };

  const dirInput = useRef<HTMLInputElement>(null);
  const importInput = useRef<HTMLInputElement>(null);
  useEffect(() => {
    // React の型に無い属性のため DOM で付与（D&D 非対応環境のフォルダ選択フォールバック、F-02）
    dirInput.current?.setAttribute('webkitdirectory', '');
    dirInput.current?.setAttribute('directory', '');
  }, []);

  // 実行中のスキャン。クリア・次のスキャンで中断し、その結果は reducer が scanId の不一致で捨てる
  const current = useRef<AbortController | null>(null);
  const nextId = useRef(0);
  const cancelScan = () => { current.current?.abort(); current.current = null; };
  const clear = () => { cancelScan(); setSpecimen(null); dispatch({ type: 'CLEAR' }); };

  const scan = async (picked: PickedFile[]) => {
    if (!picked.length) {
      // 何も起きないと「安全」と誤認させるため、0 件であることを必ず知らせる（隠しファイルを渡さないブラウザがある）
      toast({ tone: 'error', text: 'ファイルが 0 件でした。隠しファイル（.mcp.json 等）だけのフォルダはブラウザによって渡されません。ドラッグ＆ドロップか CLI で確認してください' });
      return;
    }
    cancelScan();
    const scanId = ++nextId.current;
    const ctl = new AbortController();
    current.current = ctl;
    const t0 = performance.now();
    setSpecimen(specimenOf(picked));
    dispatch({ type: 'SCAN_START', scanId, total: picked.length, startedAt: nowIso() });
    try {
      const files = await readFiles(picked, (n) => dispatch({ type: 'SCAN_PROGRESS', scanId, processed: n }), ctl.signal);
      dispatch({ type: 'SCAN_PROGRESS', scanId, processed: picked.length, phase: 'analyzing' });
      const result = await analyzeFiles(files);
      if (ctl.signal.aborted) return;
      dispatch({ type: 'SCAN_RESULT', scanId, result, finishedAt: nowIso(), durationMs: performance.now() - t0 });
    } catch (e) {
      if (ctl.signal.aborted) return; // クリア・次のスキャンで中断（エラーではない）
      dispatch({ type: 'SCAN_FAIL', scanId, message: e instanceof Error ? e.message : String(e) });
      toast({ tone: 'error', text: '判定中にエラーが発生しました（結果は表示しません）' });
    }
  };

  const paste = async (text: string) => {
    dispatch({ type: 'PASTE_RESULT', findings: await analyzePaste(text) });
    setSpecimen((s) => s ?? '貼り付けたテキスト');
    setPasteOpen(false);
    toast({ tone: 'ok', text: '貼り付けテキストを判定しました（内容は保持しません）' });
  };

  const tabFindings = useMemo(() => findingsForTab(tab, findings), [tab, findings]);
  const modules = useMemo(() => [...new Set(tabFindings.map((f) => f.module))].sort((a, b) => Number(a.slice(1)) - Number(b.slice(1))), [tabFindings]);
  // このタブに無いモジュールの絞り込みは効かせない（選択欄が「すべて」なのに全行が消える状態を作らない）。SET_TAB でも消す
  const moduleFilter = state.ui.moduleFilter && modules.includes(state.ui.moduleFilter) ? state.ui.moduleFilter : null;
  useEffect(() => { if (state.ui.moduleFilter && !moduleFilter) dispatch({ type: 'SET_MODULE', module: null }); }, [state.ui.moduleFilter, moduleFilter, dispatch]);
  const visible = useMemo(() => {
    const q = state.ui.query.trim().toLowerCase();
    return tabFindings.filter((f: Finding) =>
      state.ui.severityFilter.has(f.level) && (!moduleFilter || f.module === moduleFilter)
      && (!q || String(f.path ?? '').toLowerCase().includes(q) || String(f.campaign ?? '').toLowerCase().includes(q)));
  }, [tabFindings, state.ui.severityFilter, state.ui.query, moduleFilter]);
  const sevCounts = useMemo(() => Object.fromEntries(SEVERITIES.map((s) => [s, tabFindings.filter((f) => f.level === s).length])) as Record<Severity, number>, [tabFindings]);
  const counts = useMemo(() => tabCounts(findings), [findings]);

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
      setSpecimen((s) => s ?? file.name);
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
  const clearChecks = r ? r.checksRun.filter((c) => !hitChecks.has(c)).length : 0;
  const empty = state.phase === 'idle' && !findings.length ? 'フォルダを投入するか、テキストを貼り付けてください' : findings.length ? '条件に一致する検出はありません' : '検出なし（ブラウザで判定できる範囲内。ホスト検査は CLI で実施）';
  const und = r ? r.stats.skippedSize + r.stats.skippedBinary + r.stats.zeroByteDecoys + r.stats.errors : null;

  const status: SpecimenStatus = busy
    ? { kind: 'busy', text: state.phase === 'reading' ? '読み取り中' : '判定中', sub: `${state.progress.processed.toLocaleString()} / ${state.progress.total.toLocaleString()} ファイル` }
    : state.phase === 'error' ? { kind: 'error', text: 'エラー', sub: state.errorMessage ?? '' }
      : r ? { kind: 'done', text: 'スキャン完了', sub: 'ドロップで差し替え' }
        : state.imported ? { kind: 'imported', text: '取り込み完了', sub: 'CLI の findings.json' }
          : { kind: 'pasted', text: '判定完了', sub: '貼り付けたテキスト' };
  const started = state.phase !== 'idle' || !!state.imported || state.pasteFindings.length > 0;
  const pickFolder = () => dirInput.current?.click();
  const pickImport = () => importInput.current?.click();
  const dropFolder = async (dt: DataTransfer) => {
    let picked: PickedFile[];
    try { picked = await fromDataTransfer(dt); } catch {
      // 読めなかったことを黙って捨てない（何も起きないと「問題なし」と誤認させる）
      toast({ tone: 'error', text: 'ドロップしたフォルダを読み取れませんでした。「フォルダを選択…」か CLI で確認してください' });
      return;
    }
    await scan(picked);
  };

  // ドロップ先の外にファイルを落としても、ブラウザがそのファイルへ移動しない（file:// の画面が消え、
  // ローカルのファイルを開いてしまう）。ファイルのドラッグだけを扱い、テキストのドラッグ（貼り付け欄など）は既定のまま。
  // ドロップ先が処理したもの（defaultPrevented）は二重に扱わない。それ以外はドロップ先と同じくスキャンへ回す。
  const dropRef = useRef({ busy, dropFolder });
  dropRef.current = { busy, dropFolder };
  useEffect(() => {
    const hasFiles = (e: DragEvent) => !!e.dataTransfer && [...e.dataTransfer.types].includes('Files');
    const over = (e: DragEvent) => { if (!hasFiles(e) || e.defaultPrevented) return; e.preventDefault(); e.dataTransfer!.dropEffect = 'copy'; };
    const drop = (e: DragEvent) => {
      if (!hasFiles(e) || e.defaultPrevented) return;
      e.preventDefault();
      const { busy: b, dropFolder: go } = dropRef.current;
      if (b) toast({ tone: 'error', text: '判定中です。終わってから検体票（ドロップ先）へドロップしてください' });
      else void go(e.dataTransfer!);
    };
    window.addEventListener('dragover', over);
    window.addEventListener('drop', drop);
    return () => { window.removeEventListener('dragover', over); window.removeEventListener('drop', drop); };
  }, [toast]);

  return (
    <div className="min-h-full">
      <Header onExport={exportJson} onClear={clear} onImport={pickImport} canExport={!busy && (findings.length > 0 || !!r)} />
      <input ref={dirInput} type="file" multiple hidden data-testid="dir-input" onChange={(e) => { if (e.target.files?.length) scan(fromFileList(e.target.files)); e.target.value = ''; }} />
      <input ref={importInput} type="file" accept=".json,application/json" hidden data-testid="import-input" onChange={(e) => { const f = e.target.files?.[0]; if (f) importJson(f); e.target.value = ''; }} />
      <Tabs value={tab.id} onValueChange={(id) => dispatch({ type: 'SET_TAB', tab: id as TabId })} activationMode="manual">
        <TabBar active={tab.id} counts={counts} onPick={(id) => dispatch({ type: 'SET_TAB', tab: id })} mobile={mobile} />
        <TabsContent value={tab.id} asChild>
          <main className="px-6 pt-6 pb-16 focus-visible:outline-offset-[-2px] max-lg:px-4 max-sm:pt-3">
            <ErrorBoundary onReset={clear}>
              {tab.id === 'skillpact' ? (
                <SkillPactTab skills={r?.skillpact ?? []} selected={state.ui.selectedSkillId} onSelect={(id) => dispatch({ type: 'SELECT_SKILL', id })} />
              ) : (
                <div className="grid grid-cols-[minmax(0,1fr)_320px] gap-8 max-xl:grid-cols-[minmax(0,1fr)_300px] max-lg:grid-cols-1">
                  <div className="flex min-w-0 flex-col gap-4 max-sm:gap-3">
                    {tab.id === 'overview' && (started
                      ? <SpecimenForm name={specimen ?? '—'} files={r ? r.stats.files.toLocaleString() : '—'} duration={r ? `${(state.durationMs / 1000).toFixed(1)} 秒` : '—'}
                          undetermined={und === null ? '—' : `${und.toLocaleString()} 件`} status={status} busy={busy} onDrop={dropFolder} onPick={pickFolder} />
                      : <Intake busy={busy} onDrop={dropFolder} onPick={pickFolder} onImport={pickImport} />)}
                    {tab.id === 'overview' && mobile && started && (
                      <div className="flex gap-2">
                        <Button variant="ink" size="touch" disabled={busy} onClick={pickFolder} className="flex-1 justify-start"><FolderOpen />フォルダを選択…</Button>
                        <Button variant="outline" size="icon-touch" aria-label="テキスト貼り付け判定" data-paste-opener onClick={openPaste}><ClipboardPaste /></Button>
                      </div>
                    )}
                    {tab.id === 'overview' && mobile && !started && (
                      <Button variant="outline" size="touch" data-paste-opener onClick={openPaste}><ClipboardPaste />テキスト貼り付け判定</Button>
                    )}
                    {state.imported && (
                      <p className="text-xs text-muted-foreground" data-testid="import-status">
                        CLI 取り込み: {state.imported.findings.length} 件（status: {state.imported.status}）
                        {state.imported.dropped > 0 && <span className="text-high">。スキーマ不適合で除外 {state.imported.dropped} 件</span>}
                      </p>
                    )}
                    {tab.cliOnlyNote && <CliOnlyNotice note={tab.cliOnlyNote} compact />}
                    <div className="mt-1 max-sm:mt-0"><Tally counts={sevCounts} active={state.ui.severityFilter} onToggle={(s) => dispatch({ type: 'TOGGLE_SEVERITY', severity: s })} safe={{ clear: clearChecks, total }} mobile={mobile} /></div>
                    {mobile
                      ? <FindingList findings={visible} empty={empty} query={state.ui.query} onQuery={(q) => dispatch({ type: 'SET_QUERY', query: q })} modules={modules} module={moduleFilter} onModule={(m) => dispatch({ type: 'SET_MODULE', module: m })} />
                      : <FindingsTable findings={visible} total={tabFindings.length} empty={empty} query={state.ui.query} onQuery={(q) => dispatch({ type: 'SET_QUERY', query: q })} modules={modules} module={moduleFilter} onModule={(m) => dispatch({ type: 'SET_MODULE', module: m })} />}
                    {tab.viewer === 'mcp' && <McpViewer configs={r?.viewers.mcp ?? []} />}
                    {tab.viewer === 'actions' && <ActionsViewer workflows={r?.viewers.actions ?? []} />}
                    {tab.viewer === 'extensions' && <ExtensionViewer manifests={r?.viewers.extensions ?? []} />}
                  </div>
                  <aside aria-label="欄外" className="flex min-w-0 flex-col gap-4 max-lg:grid max-lg:grid-cols-2 max-lg:gap-x-8 max-sm:flex max-sm:pt-2 [&>*+*]:border-t [&>*+*]:border-border [&>*+*]:pt-4 max-lg:[&>*:nth-child(2)]:border-t-0 max-lg:[&>*:nth-child(2)]:pt-0 max-sm:[&>*:nth-child(2)]:border-t max-sm:[&>*:nth-child(2)]:pt-4">
                    {tab.id === 'overview' && !mobile && <PasteCheck onPaste={paste} />}
                    <BlastRadius items={r?.blastRadius ?? []} />
                    <CliOnlyNotice />
                    <Undetermined skippedSize={r?.stats.skippedSize ?? 0} skippedBinary={r?.stats.skippedBinary ?? 0} decoys={r?.stats.zeroByteDecoys ?? 0} errors={r?.stats.errors ?? 0} />
                  </aside>
                </div>
              )}
            </ErrorBoundary>
          </main>
        </TabsContent>
      </Tabs>
      {mobile && (
        <Sheet open={pasteOpen} onOpenChange={setPasteOpen}>
          <SheetContent title="テキスト貼り付け判定" onCloseAutoFocus={returnPasteFocus} className="pb-[max(env(safe-area-inset-bottom),16px)]">
            <PasteCheck onPaste={paste} inSheet />
          </SheetContent>
        </Sheet>
      )}
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

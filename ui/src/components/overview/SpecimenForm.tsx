// 検体票（設計書 §10.3、§10.4）。投入したものの記録: 検体、ファイル、判定時間、未判定、実行 0 回、状態。
// この画面でいちばん目立つ要素（等幅 26px のパス）。台紙全体がドロップ先で、dragover で破線の縁になる。
// スキャン前は Intake（大きな破線のドロップ先）を出す。
import { useState, type DragEvent, type ReactNode } from 'react';
import { Check, FolderOpen, Hourglass, OctagonAlert, Upload } from 'lucide-react';
import { useMediaQuery } from '@/hooks/useMediaQuery';
import { cn } from '@/lib/utils';
import { visiblePath } from '@/lib/visiblePath';
import { Button } from '@/components/ui/button';
import { Tip } from '@/components/ui/tooltip';

export interface SpecimenStatus {
  kind: 'busy' | 'done' | 'imported' | 'pasted' | 'error';
  text: string;
  sub: string;
}

function useDrop(busy: boolean, onDrop: (dt: DataTransfer) => void) {
  const [over, setOver] = useState(false);
  return {
    over,
    handlers: {
      onDragOver: (e: DragEvent) => { e.preventDefault(); setOver(true); },
      onDragLeave: () => setOver(false),
      onDrop: (e: DragEvent) => { e.preventDefault(); setOver(false); if (!busy) onDrop(e.dataTransfer); },
    },
  };
}

/** スキャン前: 検体票の位置に大きなドロップ先（破線、中央揃え）。 */
export function Intake({ busy, onDrop, onPick, onImport }: { busy: boolean; onDrop(dt: DataTransfer): void; onPick(): void; onImport(): void }) {
  const { over, handlers } = useDrop(busy, onDrop);
  return (
    <div {...handlers} data-testid="dropzone" className={cn('flex min-h-[188px] flex-col items-center justify-center gap-1 rounded-md border-[1.5px] border-dashed px-6 py-8 text-center', over ? 'border-foreground bg-accent' : 'border-input')}>
      <h2 className="text-[21px] font-semibold">フォルダをドロップして判定</h2>
      <p className="text-[13px] text-muted-foreground">内容は判定にのみ使い、表示・保存・送信しません</p>
      <div className="mt-4 flex flex-wrap items-center justify-center gap-2">
        <Button variant="ink" disabled={busy} onClick={onPick} className="max-sm:h-11"><FolderOpen />フォルダを選択…</Button>
        <Button variant="ghost" onClick={onImport} className="max-sm:h-11"><Upload />findings.json を読み込む</Button>
      </div>
    </div>
  );
}

function Field({ label, children, tip, className }: { label: string; children: ReactNode; tip?: string; className?: string }) {
  const value = <span className="text-[17px] font-semibold tabular-nums max-xl:text-sm">{children}</span>;
  return (
    <div className={cn('flex min-w-0 flex-col justify-center gap-1 px-[18px] max-xl:gap-0.5 max-xl:px-3 max-xl:py-2.5', className)}>
      <span className="text-xs text-muted-foreground max-xl:text-[11.5px]">{label}</span>
      {tip ? <Tip label={tip}><span tabIndex={0} className="w-fit rounded-sm">{value}</span></Tip> : value}
    </div>
  );
}

const STATUS_ICON = { busy: Hourglass, done: Check, imported: Check, pasted: Check, error: OctagonAlert };

export function SpecimenForm({ name, files, duration, undetermined, status, busy, onDrop, onPick }: {
  name: string; files: string; duration: string; undetermined: string; status: SpecimenStatus; busy: boolean;
  onDrop(dt: DataTransfer): void; onPick(): void;
}) {
  const { over, handlers } = useDrop(busy, onDrop);
  // 検体名は投入したフォルダ・ファイルの名前（信頼できない）。制御文字・双方向制御文字を目印にして、<bdi> で切り離す
  const shown = visiblePath(name);
  // data-testid=scan-status を 1 つにするため、CSS で隠さずに片方だけを描く
  const wide = useMediaQuery('(min-width: 1280px)');
  const Icon = STATUS_ICON[status.kind];
  const statusCell = (
    <div className="flex min-w-0 flex-col gap-1" aria-live="polite" data-testid="scan-status">
      <span className={cn('flex min-w-0 items-center gap-1.5 text-[13px] font-semibold max-xl:text-[12.5px]', status.kind === 'error' && 'text-critical')}>
        <Icon aria-hidden="true" strokeWidth={2.25} className={cn('size-[15px] shrink-0', status.kind === 'error' ? 'text-critical' : 'text-muted-foreground')} />
        {status.text}
      </span>
      {status.sub && <span className={cn('truncate text-xs text-muted-foreground tabular-nums', !wide && status.kind !== 'busy' && 'hidden')}>{status.sub}</span>}
    </div>
  );
  const pick = (
    <Button variant="ink" size="sm" disabled={busy} onClick={onPick} className="h-9 max-sm:hidden"><FolderOpen />フォルダを選択…</Button>
  );
  return (
    <section {...handlers} data-testid="dropzone" aria-label="検体票"
      className={cn('min-w-0 rounded-md border bg-card', over ? 'border-dashed border-foreground outline-1 outline-foreground' : 'border-border')}>
      {/* ≥1280: 1 段（検体 280 | 4 欄 | 状態と操作） */}
      {wide ? (
      <div className="grid h-[86px] grid-cols-[280px_repeat(4,100px)_minmax(0,1fr)]">
        <div className="flex min-w-0 flex-col justify-center gap-0.5 border-r border-border px-5">
          <span className="text-xs text-muted-foreground">検体</span>
          <bdi dir="ltr" data-testid="specimen-name" className="block truncate font-mono text-[26px] leading-[1.2] font-semibold" title={shown}>{shown}</bdi>
        </div>
        <Field label="ファイル">{files}</Field>
        <Field label="判定時間" className="border-l border-dotted border-border">{duration}</Field>
        <Field label="未判定" className="border-l border-dotted border-border">{undetermined}</Field>
        <Field label="実行" className="border-l border-dotted border-border" tip="ZES はファイルを実行・インストールしません">0 回</Field>
        <div className="flex min-w-0 items-center justify-between gap-3 border-l border-border pr-4 pl-5">
          {statusCell}
          {pick}
        </div>
      </div>
      ) : (
      /* <1280: 2 段（パスと状態 / 4 欄） */
      <div>
        <div className="flex min-w-0 items-start gap-3 px-3.5 pt-2.5 pb-3">
          <div className="flex min-w-0 flex-1 flex-col">
            <span className="text-xs text-muted-foreground">検体</span>
            <bdi dir="ltr" data-testid="specimen-name" className="block truncate font-mono text-[22px] leading-[1.25] font-semibold" title={shown}>{shown}</bdi>
          </div>
          <div className="flex max-w-[62%] min-w-0 items-center gap-3 pt-0.5">{statusCell}{pick}</div>
        </div>
        <div className="grid grid-cols-4 border-t border-border">
          <Field label="ファイル">{files}</Field>
          <Field label="判定時間" className="border-l border-border">{duration}</Field>
          <Field label="未判定" className="border-l border-border">{undetermined}</Field>
          <Field label="実行" className="border-l border-border" tip="ZES はファイルを実行・インストールしません">0 回</Field>
        </div>
      </div>
      )}
    </section>
  );
}

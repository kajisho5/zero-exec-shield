// 欄外（設計書 §10.3 の右の列）。カードにせず、作業台の上に置いて罫で区切る注記。見出しの前にアイコンは置かない。
// テキスト貼り付け判定 / Blast Radius / ホスト検査は CLI で / 未判定の内訳。
import { useState, type ReactNode } from 'react';
import { CircleDashed, Copy } from 'lucide-react';
import type { BlastRadiusItem } from '@/engine';
import { CLI_COMMAND } from '@/tabs/definitions';
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
  return (
    <Note aria-label="テキスト貼り付け判定" className={inSheet ? 'px-4 pt-3' : undefined}>
      {!inSheet && <H>テキスト貼り付け判定</H>}
      <p className="text-xs text-muted-foreground">C2 ドメイン/IP・base64・exec(・curl</p>
      <Textarea
        value={text}
        maxLength={PASTE_MAX}
        onChange={(e) => setText(e.target.value)}
        aria-label="判定するテキスト"
        data-testid="paste"
        placeholder={'ログ・コマンド履歴・設定断片を貼り付け\n（貼り付け内容は再表示しません）'}
        className="mt-2.5 h-[84px]"
      />
      <div className="mt-2.5 flex items-center justify-between gap-3">
        <span className="text-xs text-muted-foreground tabular-nums">{text.length.toLocaleString()} / {PASTE_MAX.toLocaleString()} 文字</span>
        <Button variant="outline" size="sm" disabled={!text.trim()} onClick={() => { onPaste(text); setText(''); }} data-testid="paste-submit" className="w-[92px]">判定する</Button>
      </div>
    </Note>
  );
}

export function BlastRadius({ items }: { items: BlastRadiusItem[] }) {
  const copy = useCopy();
  const size = (n: number) => (n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`);
  return (
    <Note data-testid="blast-radius">
      <div className="flex flex-wrap items-center gap-2.5"><H>Blast Radius</H><Tag>存在のみ・内容非表示</Tag></div>
      <p className="mt-2 text-[12.5px] leading-[1.45] text-muted-foreground">ローテーション対象のシークレットのパス一覧<br />（§14 / §19 / §9.5）</p>
      {items.length === 0 ? (
        <div className="mt-3 flex h-11 items-center gap-2.5 rounded-md border border-dashed border-input px-3.5 text-[13px] text-muted-foreground">
          <CircleDashed aria-hidden="true" className="size-4 shrink-0" />該当なし（投入フォルダ内のみ判定）
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
      <p className="mt-3.5 text-xs text-muted-foreground">{items.length} 件・内容は読み取り・表示しません</p>
      <div className="mt-2 flex flex-wrap items-start justify-between gap-x-3 gap-y-2">
        <p className="max-w-[13.5em] min-w-[12.5em] flex-1 text-xs leading-normal text-muted-foreground">手順: 検出 → 一覧提示 → ローテーション → 再構築</p>
        <Button size="sm" disabled={!items.length} onClick={() => copy(items.map((b) => b.path).join('\n'), 'パス一覧') /* コピーは元の値のまま */} className="shrink-0"><Copy />パス一覧をコピー</Button>
      </div>
    </Note>
  );
}

function Command({ label }: { label?: string }) {
  const copy = useCopy();
  return (
    <div className="flex h-10 min-w-0 items-center justify-between gap-2 rounded-md border border-border bg-muted pr-1 pl-3">
      <code className="min-w-0 truncate font-mono text-[13px]">{CLI_COMMAND}</code>
      <Tip label="コマンドをコピー" side="left">
        <Button variant="ghost" size="icon-sm" aria-label={label ?? 'コマンドをコピー'} onClick={() => copy(CLI_COMMAND, 'コマンド')}><Copy /></Button>
      </Tip>
    </div>
  );
}

export function CliOnlyNotice({ note, compact }: { note?: string; compact?: boolean }) {
  if (compact) {
    return (
      <Note data-testid="cli-only" className="gap-2 border-y border-border py-3 sm:flex-row sm:items-center sm:gap-4">
        <p className="min-w-0 flex-1 text-[13px] text-muted-foreground"><span className="font-semibold text-foreground">CLI で確認: </span>{note}</p>
        <div className="sm:w-[300px]"><Command /></div>
      </Note>
    );
  }
  return (
    <Note data-testid="cli-only">
      <H>ホスト検査は CLI で実施</H>
      <p className="mt-2 text-[13px] leading-[1.55] text-muted-foreground">{note ?? 'プロセス・ネットワーク接続・カーネル・eBPF・マウント状態はブラウザから確認できないため、0 件 ＝ 安全と表示しません。'}</p>
      <div className="mt-3"><Command /></div>
    </Note>
  );
}

export function Undetermined({ skippedSize, skippedBinary, decoys, errors }: { skippedSize: number; skippedBinary: number; decoys: number; errors: number }) {
  const rows: [string, number][] = [['サイズ超過（2 MiB 超）', skippedSize], ['バイナリ（判定対象外）', skippedBinary], ['シンボリックリンク先不明（0 バイトのデコイ）', decoys], ['読み取り失敗', errors]];
  return (
    <Note data-testid="undetermined">
      <H>未判定（0 件扱いしない）</H>
      <dl className="mt-1.5">
        {rows.map(([k, v]) => (
          <div key={k} className="flex items-baseline justify-between gap-3 border-b border-dotted border-border py-[7px] text-[13px] last:border-0">
            <dt className="min-w-0">{k}</dt><dd className="font-medium tabular-nums">{v}</dd>
          </div>
        ))}
      </dl>
    </Note>
  );
}

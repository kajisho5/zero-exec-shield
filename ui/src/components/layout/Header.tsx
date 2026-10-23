// ヘッダー（設計書 §10.1）。作業台と同じ地で、下に罫 1px。
// ≥1280: ロゴ、版、bundle ID、外部通信ゼロのタグ、読み込む / JSON 出力 / クリア / テーマ。
// 1024–1279: bundle ID は版の Tooltip へ。768–1023: JSON 出力と「…」。<640: マーク＋ワードマーク、テーマ、「…」（44px）。
import { Copy, Download, Ellipsis, Trash, Upload, WifiOff } from 'lucide-react';
import { IOC } from '@/engine';
import { Mark, Wordmark } from '@/components/brand/Logo';
import { Tag } from '@/components/severity/Tag';
import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { useCopy } from '@/components/ui/toast';
import { Tip } from '@/components/ui/tooltip';
import { ThemeToggle } from './ThemeToggle';

const CSP_NOTE = "この画面は外部と一切通信しません（CSP connect-src 'none'、Web フォント・CDN なし）";

export function Header({ onExport, onClear, onImport, canExport }: { onExport(): void; onClear(): void; onImport(): void; canExport: boolean }) {
  const copy = useCopy();
  return (
    <header className="flex h-14 items-center gap-5 border-b border-border px-6 max-lg:px-4 max-sm:h-[52px] max-sm:gap-1">
      <h1 aria-label="zero-exec shield" className="flex shrink-0 items-center gap-2.5">
        <Mark size={28} />
        <Wordmark height={15.5} className="max-sm:h-[14.5px] max-sm:w-auto max-[359px]:hidden" />
      </h1>
      <Tip label={<>準拠仕様 v5.2<span className="xl:hidden"><br />bundle {IOC.incident_bundle}</span></>}>
        <span tabIndex={0} className="shrink-0 rounded-sm text-xs text-muted-foreground tabular-nums max-sm:hidden">v0.1.0</span>
      </Tip>
      <span className="min-w-0 truncate font-mono text-[13px] text-muted-foreground max-xl:hidden" data-testid="bundle">{IOC.incident_bundle}</span>
      <div className="ml-auto flex shrink-0 items-center gap-1">
        <Tip label={CSP_NOTE}>
          <span tabIndex={0} className="mr-3 rounded-sm max-lg:hidden"><Tag icon={<WifiOff strokeWidth={2.25} />}>オフライン・外部通信ゼロ</Tag></span>
        </Tip>
        <Button variant="ghost" onClick={onImport} className="max-lg:hidden"><Upload />findings.json を読み込む</Button>
        <Button variant="outline" onClick={onExport} disabled={!canExport} data-testid="export" className="mx-1 max-md:hidden"><Download />JSON 出力</Button>
        <Button variant="ghost" onClick={onClear} className="max-lg:hidden"><Trash />クリア</Button>
        <ThemeToggle className="max-sm:size-11" />
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="icon" aria-label="その他の操作" className="lg:hidden max-sm:size-11"><Ellipsis /></Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="w-72">
            <DropdownMenuLabel className="flex items-center gap-1.5"><WifiOff aria-hidden="true" strokeWidth={2.25} className="size-3" />オフライン・外部通信ゼロ</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={onExport} disabled={!canExport} className="md:hidden"><Download />JSON 出力</DropdownMenuItem>
            <DropdownMenuItem onSelect={onImport}><Upload />findings.json を読み込む</DropdownMenuItem>
            <DropdownMenuItem onSelect={onClear}><Trash />クリア</DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => copy(IOC.incident_bundle, 'bundle ID ')} className="flex-col items-start gap-0.5 py-1.5">
              <span className="flex items-center gap-2 text-xs text-muted-foreground"><Copy className="size-3.5" />bundle ID をコピー</span>
              <span className="font-mono text-[12.5px] wrap-anywhere">{IOC.incident_bundle}</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}

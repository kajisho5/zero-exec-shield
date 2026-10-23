// Header (design doc §10.1). Same ground as the bench, with a 1px rule below.
// ≥1280: logo, version, bundle ID, the zero-network tag, Load / Export JSON / Clear / language / theme.
// The language buttons only at ≥640. Below 640 they are radio items inside "…" (i18n mockup header-en).
// 1024–1279: bundle ID moves into the version Tooltip. 768–1023: Export JSON and "…". <640: mark + wordmark, theme, "…" (44px).
import { Copy, Download, Ellipsis, Trash, Upload, WifiOff } from 'lucide-react';
import { IOC } from '@/engine';
import { Mark, Wordmark } from '@/components/brand/Logo';
import { Tag } from '@/components/severity/Tag';
import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { useCopy } from '@/components/ui/toast';
import { Tip } from '@/components/ui/tooltip';
import { useLang } from '@/i18n';
import { LangRadio, LangToggle } from './LangToggle';
import { ThemeToggle } from './ThemeToggle';

export function Header({ onExport, onClear, onImport, canExport }: { onExport(): void; onClear(): void; onImport(): void; canExport: boolean }) {
  const copy = useCopy();
  const { t } = useLang();
  return (
    <header className="flex h-14 items-center gap-5 border-b border-border px-6 max-lg:px-4 max-sm:h-[52px] max-sm:gap-1">
      <h1 aria-label="zero-exec shield" className="flex shrink-0 items-center gap-2.5">
        <Mark size={28} />
        <Wordmark height={15.5} className="max-sm:h-[14.5px] max-sm:w-auto max-[359px]:hidden" />
      </h1>
      <Tip label={<>{t('ui.header.spec_tip')}<span className="xl:hidden"><br />bundle {IOC.incident_bundle}</span></>}>
        <span tabIndex={0} className="shrink-0 rounded-sm text-xs text-muted-foreground tabular-nums max-sm:hidden">v{__ZES_UI_VERSION__}</span>
      </Tip>
      <span className="min-w-0 truncate font-mono text-[13px] text-muted-foreground max-xl:hidden" data-testid="bundle">{IOC.incident_bundle}</span>
      <div className="ml-auto flex shrink-0 items-center gap-1">
        <Tip label={t('ui.header.csp_note')}>
          <span tabIndex={0} className="mr-3 rounded-sm max-lg:hidden"><Tag icon={<WifiOff strokeWidth={2.25} />}>{t('ui.header.offline_tag')}</Tag></span>
        </Tip>
        <Button variant="ghost" onClick={onImport} className="max-lg:hidden"><Upload />{t('ui.header.import')}</Button>
        <Button variant="outline" onClick={onExport} disabled={!canExport} data-testid="export" className="mx-1 max-md:hidden"><Download />{t('ui.header.export')}</Button>
        <Button variant="ghost" onClick={onClear} className="max-lg:hidden"><Trash />{t('ui.header.clear')}</Button>
        <LangToggle className="gap-1.5 px-2.5 max-sm:hidden" />
        <ThemeToggle className="max-sm:size-11" />
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="icon" aria-label={t('ui.header.more')} className="lg:hidden max-sm:size-11"><Ellipsis /></Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="w-72">
            <DropdownMenuLabel className="flex items-center gap-1.5"><WifiOff aria-hidden="true" strokeWidth={2.25} className="size-3" />{t('ui.header.offline_tag')}</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={onExport} disabled={!canExport} className="md:hidden"><Download />{t('ui.header.export')}</DropdownMenuItem>
            <DropdownMenuItem onSelect={onImport}><Upload />{t('ui.header.import')}</DropdownMenuItem>
            <DropdownMenuItem onSelect={onClear}><Trash />{t('ui.header.clear')}</DropdownMenuItem>
            <DropdownMenuSeparator />
            {/* <640 has no language button: the radio group sits here, above Copy bundle ID */}
            <div className="sm:hidden" data-testid="lang-menu">
              <LangRadio />
              <DropdownMenuSeparator />
            </div>
            <DropdownMenuItem onSelect={() => copy(IOC.incident_bundle, t('ui.copy.bundle'))} className="flex-col items-start gap-0.5 py-1.5">
              <span className="flex items-center gap-2 text-xs text-muted-foreground"><Copy className="size-3.5" />{t('ui.header.copy_bundle')}</span>
              <span className="font-mono text-[12.5px] wrap-anywhere">{IOC.incident_bundle}</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}

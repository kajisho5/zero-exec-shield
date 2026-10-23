// Language switch (i18n DESIGN §3.4, mockup header-en). ≥640: a ghost button (Languages icon + "EN" / "JA") left of the
// theme button, with a menu. <640: no button; the "…" menu holds the same radio group (LangRadio).
// Each language is named in its own language (English / 日本語), and 日本語 carries lang="ja" for the Japanese font.
import { Languages } from 'lucide-react';
import { LANGS, useLang, type Lang } from '@/i18n';
import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuLabel, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';

const NAME: Record<Lang, string> = { en: 'English', ja: '日本語' };

export function LangRadio() {
  const { lang, t, setLang } = useLang();
  return (
    <>
      <DropdownMenuLabel>{t('ui.lang.title')}</DropdownMenuLabel>
      <DropdownMenuRadioGroup value={lang} onValueChange={(v) => setLang(v as Lang)}>
        {LANGS.map((l) => <DropdownMenuRadioItem key={l} value={l} lang={l} data-testid={`lang-${l}`}>{NAME[l]}</DropdownMenuRadioItem>)}
      </DropdownMenuRadioGroup>
    </>
  );
}

export function LangToggle({ className }: { className?: string }) {
  const { lang, t } = useLang();
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" className={className} aria-label={t('ui.lang.button', { current: NAME[lang] })} data-testid="lang">
          <Languages />{t('ui.lang.short')}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent className="w-60">
        <LangRadio />
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

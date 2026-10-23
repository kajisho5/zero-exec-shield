// Theme switch: a ghost icon button + menu (dark / light / match system). design doc §5.4.
import { Moon, Sun } from 'lucide-react';
import { useTheme, type ThemePref } from '@/hooks/useTheme';
import { useLang } from '@/i18n';
import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuLabel, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';

const LABEL = { dark: 'ui.theme.dark', light: 'ui.theme.light', system: 'ui.theme.system' } as const;

export function ThemeToggle({ className }: { className?: string }) {
  const { pref, resolved, setTheme } = useTheme();
  const { t } = useLang();
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" className={className} aria-label={t('ui.theme.button', { pref: t(LABEL[pref]) })} data-testid="theme">
          {resolved === 'dark' ? <Sun /> : <Moon />}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent className="min-w-44">
        <DropdownMenuLabel>{t('ui.theme.title')}</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={pref} onValueChange={(v) => setTheme(v as ThemePref)}>
          {(['dark', 'light', 'system'] as const).map((p) => <DropdownMenuRadioItem key={p} value={p}>{t(LABEL[p])}</DropdownMenuRadioItem>)}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

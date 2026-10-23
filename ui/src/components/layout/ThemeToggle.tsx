// テーマ切替: ghost のアイコンボタン＋メニュー（ダーク / ライト / システムに合わせる）。設計書 §5.4。
import { Moon, Sun } from 'lucide-react';
import { useTheme, type ThemePref } from '@/hooks/useTheme';
import { Button } from '@/components/ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuLabel, DropdownMenuRadioGroup, DropdownMenuRadioItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';

const LABEL: Record<ThemePref, string> = { dark: 'ダーク', light: 'ライト', system: 'システムに合わせる' };

export function ThemeToggle({ className }: { className?: string }) {
  const { pref, resolved, setTheme } = useTheme();
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" className={className} aria-label={`テーマ（${LABEL[pref]}）`} data-testid="theme">
          {resolved === 'dark' ? <Sun /> : <Moon />}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent className="min-w-44">
        <DropdownMenuLabel>テーマ</DropdownMenuLabel>
        <DropdownMenuRadioGroup value={pref} onValueChange={(v) => setTheme(v as ThemePref)}>
          {(['dark', 'light', 'system'] as const).map((p) => <DropdownMenuRadioItem key={p} value={p}>{LABEL[p]}</DropdownMenuRadioItem>)}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

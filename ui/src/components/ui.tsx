import { Component, createContext, useCallback, useContext, useState, type ButtonHTMLAttributes, type ReactNode } from 'react';
import type { DisplaySeverity } from '../engine';

// ---- アイコン（ui-components.svg §I。12/16/32 グリッド、stroke 1.5） ----------------------
export type IconName = 'crit' | 'high' | 'medium' | 'low' | 'info' | 'safe' | 'copy' | 'key' | 'folder' | 'terminal' | 'search' | 'seal' | 'doc' | 'diff' | 'chevron-left' | 'chevron-right' | 'chevron-down' | 'brand' | 'warn';

export function Icon({ name, size = 16, className = '' }: { name: IconName; size?: number; className?: string }) {
  const p = { fill: 'none', stroke: 'currentColor', strokeWidth: 1.5, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const };
  const body: Record<IconName, ReactNode> = {
    crit: <circle cx="8" cy="8" r="5" fill="currentColor" />,
    high: <path d="M8 3 L13.5 12.5 H2.5 Z" fill="currentColor" />,
    medium: <circle cx="8" cy="8" r="4.5" fill="currentColor" />,
    low: <path d="M8 2.5 L13.5 8 L8 13.5 L2.5 8 Z" fill="currentColor" />,
    info: <circle cx="8" cy="8" r="4.5" {...p} strokeWidth={2} />,
    safe: <path d="M3.5 8.5 L6.5 11.5 L12.5 4.5" {...p} strokeWidth={2} />,
    warn: <path d="M8 2.5 L14 13 H2 Z M8 6.5 V9.5 M8 11.2 V11.3" {...p} />,
    copy: <><rect x="5.5" y="5.5" width="8" height="8" rx="1.5" {...p} /><path d="M10.5 3.5 V3 A1 1 0 0 0 9.5 2 H3 A1 1 0 0 0 2 3 V9.5 A1 1 0 0 0 3 10.5 H3.5" {...p} /></>,
    key: <><circle cx="5" cy="11" r="2.5" {...p} /><path d="M6.8 9.2 L13 3 M11 5 L12.5 6.5 M9.5 6.5 L10.5 7.5" {...p} /></>,
    folder: <><path d="M2 4.5 A1 1 0 0 1 3 3.5 H6.5 L8 5 H13 A1 1 0 0 1 14 6 V12 A1 1 0 0 1 13 13 H3 A1 1 0 0 1 2 12 Z" {...p} /><path d="M8 7 V11 M6.3 9.4 L8 11 L9.7 9.4" {...p} /></>,
    terminal: <><rect x="2" y="3" width="12" height="10" rx="1.5" {...p} /><path d="M4.5 6.5 L6.5 8.5 L4.5 10.5 M8 10.5 H11" {...p} /></>,
    search: <><circle cx="7" cy="7" r="4" {...p} /><path d="M10 10 L13.5 13.5" {...p} /></>,
    seal: <><circle cx="8" cy="8" r="5.5" {...p} /><circle cx="8" cy="8" r="2.5" {...p} /><path d="M8 2.5 V1.5 M8 14.5 V13.5 M2.5 8 H1.5 M14.5 8 H13.5" {...p} /></>,
    doc: <><path d="M4 2 H9.5 L12.5 5 V14 H4 Z" {...p} /><path d="M9.5 2 V5 H12.5" {...p} /></>,
    diff: <path d="M4 2.5 V7.5 M1.5 5 H6.5 M9 4 H14 M9 11 H14 M11.5 8.5 V13.5" {...p} />,
    'chevron-left': <path d="M10 3.5 L5.5 8 L10 12.5" {...p} />,
    'chevron-right': <path d="M6 3.5 L10.5 8 L6 12.5" {...p} />,
    'chevron-down': <path d="M3.5 6 L8 10.5 L12.5 6" {...p} />,
    brand: <><path d="M8 1.5 L13.5 3.5 V7.5 C13.5 11 11 13.5 8 14.5 C5 13.5 2.5 11 2.5 7.5 V3.5 Z" {...p} /><path d="M5.5 8 L7.3 9.8 L10.7 6.3" {...p} /></>,
  };
  return (
    <svg viewBox="0 0 16 16" width={size} height={size} className={className} aria-hidden="true" focusable="false">
      {body[name]}
    </svg>
  );
}

// ---- 重大度 ---------------------------------------------------------------------------------
export const SEV_STYLE: Record<DisplaySeverity, { fg: string; bg: string; border: string; bar: string; icon: IconName }> = {
  CRITICAL: { fg: 'text-critical', bg: 'bg-critical-bg', border: 'border-critical', bar: 'bg-critical', icon: 'crit' },
  HIGH: { fg: 'text-high', bg: 'bg-high-bg', border: 'border-high', bar: 'bg-high', icon: 'high' },
  MEDIUM: { fg: 'text-medium', bg: 'bg-medium-bg', border: 'border-medium', bar: 'bg-medium', icon: 'medium' },
  LOW: { fg: 'text-low', bg: 'bg-low-bg', border: 'border-low', bar: 'bg-low', icon: 'low' },
  INFO: { fg: 'text-info', bg: 'bg-info-bg', border: 'border-info', bar: 'bg-info', icon: 'info' },
  SAFE: { fg: 'text-safe', bg: 'bg-safe-bg', border: 'border-safe', bar: 'bg-safe', icon: 'safe' },
};

/** 色だけに依存しない（ラベル＋アイコン形状を併記、WCAG 1.4.1）。 */
export function SeverityBadge({ level, count }: { level: DisplaySeverity; count?: number }) {
  const s = SEV_STYLE[level];
  return (
    <span className={`inline-flex h-6 items-center gap-1.5 rounded-md border px-2 text-xs font-medium ${s.fg} ${s.bg} ${s.border}`} data-severity={level}>
      <Icon name={s.icon} size={12} />
      {level}
      {count !== undefined && <span>{count}</span>}
    </span>
  );
}

// ---- ボタン ---------------------------------------------------------------------------------
type Variant = 'primary' | 'secondary' | 'ghost' | 'icon';
export function Button({ variant = 'secondary', className = '', children, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }) {
  const v: Record<Variant, string> = {
    primary: 'bg-accent text-bg font-semibold hover:brightness-110 px-5',
    secondary: 'bg-surface-2 border border-border-strong text-text hover:bg-[#242424] px-5',
    ghost: 'text-text hover:bg-surface-2 px-4',
    icon: 'bg-surface-2 border border-border-strong text-muted hover:text-text w-8 justify-center',
  };
  return (
    <button type="button" className={`inline-flex h-8 items-center gap-2 rounded-lg text-sm transition disabled:opacity-40 disabled:cursor-not-allowed ${v[variant]} ${className}`} {...rest}>
      {children}
    </button>
  );
}

export function Card({ className = '', children, ...rest }: { className?: string; children: ReactNode } & React.HTMLAttributes<HTMLElement>) {
  return <section className={`rounded-xl border border-border bg-surface ${className}`} {...rest}>{children}</section>;
}

export function Pill({ tone, children, title, dashed }: { tone: 'accent' | 'muted' | 'critical' | 'high' | 'medium' | 'low' | 'signed' | 'safe'; children: ReactNode; title?: string; dashed?: boolean }) {
  const t: Record<string, string> = {
    accent: 'text-accent border-accent bg-[#0b1f2a]', muted: 'text-muted border-border-strong bg-surface-2',
    critical: 'text-critical border-critical bg-critical-bg', high: 'text-high border-high bg-high-bg', medium: 'text-medium border-medium bg-medium-bg',
    low: 'text-low border-low bg-low-bg', signed: 'text-signed border-signed bg-signed-bg', safe: 'text-safe border-safe bg-safe-bg',
  };
  return <span title={title} className={`inline-flex h-6 shrink-0 items-center gap-1 whitespace-nowrap rounded-md border px-2 font-mono text-xs ${dashed ? 'border-dashed' : ''} ${t[tone]}`}>{children}</span>;
}

// ---- トースト（aria-live=polite、右下、4 秒） ---------------------------------------------
interface ToastMsg { id: number; tone: 'ok' | 'error'; text: string; fallback?: string }
const ToastCtx = createContext<(t: Omit<ToastMsg, 'id'>) => void>(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [list, setList] = useState<ToastMsg[]>([]);
  const show = useCallback((t: Omit<ToastMsg, 'id'>) => {
    const id = Date.now() + Math.random();
    setList((l) => [...l, { ...t, id }]);
    setTimeout(() => setList((l) => l.filter((x) => x.id !== id)), t.fallback ? 12000 : 4000);
  }, []);
  return (
    <ToastCtx.Provider value={show}>
      {children}
      <div aria-live="polite" role="status" className="fixed bottom-4 right-4 z-50 flex w-[min(360px,calc(100vw-2rem))] flex-col gap-2 sm:bottom-6 sm:right-6">
        {list.map((t) => (
          <div key={t.id} className={`rounded-xl border px-4 py-3 text-sm ${t.tone === 'ok' ? 'border-border-strong bg-surface-2' : 'border-critical bg-critical-bg'}`}>
            <div className="flex items-center gap-2">
              <Icon name={t.tone === 'ok' ? 'safe' : 'crit'} size={14} className={t.tone === 'ok' ? 'text-safe' : 'text-critical'} />
              {t.text}
            </div>
            {t.fallback && <input readOnly value={t.fallback} aria-label="コピー用のパス" onFocus={(e) => e.currentTarget.select()} className="mt-2 w-full rounded-md border border-border-strong bg-bg px-2 py-1 font-mono text-xs" />}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

/** クリップボードへコピー（ネットワーク非使用）。file:// で権限が無い場合は選択可能な欄を出す。 */
export function useCopy() {
  const toast = useToast();
  return useCallback(async (text: string, label = 'パス') => {
    try {
      await navigator.clipboard.writeText(text);
      toast({ tone: 'ok', text: `${label}をクリップボードにコピーしました` });
    } catch {
      toast({ tone: 'error', text: 'クリップボードを使えません。下の欄から手動でコピーしてください', fallback: text });
    }
  }, [toast]);
}

// ---- エラー境界（描画エラーで画面全体が空白にならないようにする） ---------------------------
/** 子の描画で例外が起きたら、回復用のメッセージを出す。「クリアして再表示」で State を初期化して描画し直す。 */
export class ErrorBoundary extends Component<{ children: ReactNode; onReset(): void }, { failed: boolean }> {
  override state = { failed: false };
  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }
  override render() {
    if (!this.state.failed) return this.props.children;
    return (
      <Card className="flex flex-col items-start gap-3 border-critical p-5" role="alert" data-testid="render-error">
        <div className="flex items-center gap-2 font-semibold text-critical"><Icon name="crit" size={16} />表示中にエラーが発生しました</div>
        <p className="text-sm text-muted">取り込んだデータに表示できない値が含まれている可能性があります。結果をクリアして再表示してください（ファイル内容は外部に送信されません）。</p>
        <Button onClick={() => { this.props.onReset(); this.setState({ failed: false }); }} data-testid="render-error-reset">クリアして再表示</Button>
      </Card>
    );
  }
}

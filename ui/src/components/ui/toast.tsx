// 自作のトースト（Sonner は実行時に <style> を差し込むため採らない。設計書 §16-7）。
// 浮きの地、罫、角丸 6、影。主列の右下に出す。role="status" aria-live="polite"。
import { createContext, useCallback, useContext, useState, type ReactNode } from 'react';
import { Check, OctagonAlert, X } from 'lucide-react';
import { Button } from './button';

interface ToastMsg { id: number; tone: 'ok' | 'error'; text: string; fallback?: string }
const ToastCtx = createContext<(t: Omit<ToastMsg, 'id'>) => void>(() => {});
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [list, setList] = useState<ToastMsg[]>([]);
  const dismiss = useCallback((id: number) => setList((l) => l.filter((x) => x.id !== id)), []);
  const show = useCallback((t: Omit<ToastMsg, 'id'>) => {
    const id = Date.now() + Math.random();
    setList((l) => [...l, { ...t, id }]);
    setTimeout(() => dismiss(id), t.fallback ? 12000 : 4000);
  }, [dismiss]);
  return (
    <ToastCtx.Provider value={show}>
      {children}
      <div aria-live="polite" role="status" className="pointer-events-none fixed right-4 bottom-4 z-[60] flex w-[min(360px,calc(100vw-2rem))] flex-col gap-2 sm:bottom-5 lg:right-[368px] xl:right-[396px]">
        {list.map((t) => (
          <div key={t.id} className="pointer-events-auto relative overflow-hidden rounded-lg border border-border bg-popover py-2.5 pr-2 pl-4 text-[13.5px] font-medium shadow-lift data-[tone=error]:pl-5" data-tone={t.tone}>
            {t.tone === 'error' && <span aria-hidden="true" className="absolute inset-y-0 left-0 w-1 bg-critical" />}
            <div className="flex items-start gap-2.5">
              {t.tone === 'ok'
                ? <Check aria-hidden="true" strokeWidth={2.25} className="mt-0.5 size-4 shrink-0" />
                : <OctagonAlert aria-hidden="true" strokeWidth={2.25} className="mt-0.5 size-4 shrink-0 text-critical" />}
              <span className="min-w-0 flex-1 py-px">{t.text}</span>
              <Button variant="ghost" size="icon-sm" className="-my-1 shrink-0" aria-label="通知を閉じる" onClick={() => dismiss(t.id)}><X /></Button>
            </div>
            {t.fallback && <input readOnly value={t.fallback} aria-label="コピー用のパス" onFocus={(e) => e.currentTarget.select()} className="mt-2 mb-1 w-full rounded-md border border-input bg-muted px-2 py-1 font-mono text-xs" />}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

/** クリップボードへコピー（ネットワーク非使用）。file:// で権限が無い場合は選択できる欄を出す。 */
export function useCopy() {
  const toast = useToast();
  return useCallback(async (text: string, label = 'パス') => {
    try {
      await navigator.clipboard.writeText(text);
      toast({ tone: 'ok', text: `${label}をコピーしました` });
    } catch {
      toast({ tone: 'error', text: 'クリップボードを使えません。下の欄から手動でコピーしてください', fallback: text });
    }
  }, [toast]);
}

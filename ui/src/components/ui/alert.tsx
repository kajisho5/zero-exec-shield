// The shadcn/ui new-york-v4 alert (destructive), imported by hand and rewritten for the "quarantine bench" (MIT; see NOTICE).
// A CRITICAL band on a sheet. Used for recovery from render errors (ErrorBoundary).
import { Component, type ReactNode } from 'react';
import { OctagonAlert } from 'lucide-react';
import { t } from '@/i18n';
import { Button } from './button';

export function Alert({ title, children, ...rest }: { title: ReactNode; children: ReactNode } & React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div role="alert" className="relative overflow-hidden rounded-md border border-border bg-card py-4 pr-5 pl-6" {...rest}>
      <span aria-hidden="true" className="absolute inset-y-0 left-0 w-1 bg-critical" />
      <div className="flex items-center gap-2 font-semibold text-critical"><OctagonAlert aria-hidden="true" strokeWidth={2.25} className="size-4" />{title}</div>
      <div className="mt-2 flex flex-col items-start gap-3 text-sm text-muted-foreground">{children}</div>
    </div>
  );
}

/** Shows a recovery message when rendering a child throws. "Clear and redisplay" resets the State and renders again. */
export class ErrorBoundary extends Component<{ children: ReactNode; onReset(): void }, { failed: boolean }> {
  override state = { failed: false };
  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }
  override render() {
    if (!this.state.failed) return this.props.children;
    return (
      <Alert title={t('ui.error.title')} data-testid="render-error">
        <p>{t('ui.error.body')}</p>
        <Button onClick={() => { this.props.onReset(); this.setState({ failed: false }); }} data-testid="render-error-reset">{t('ui.error.reset')}</Button>
      </Alert>
    );
  }
}

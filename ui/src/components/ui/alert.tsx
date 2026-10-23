// shadcn/ui new-york-v4 の alert（destructive）を手で取り込み、「検疫台」に書き換えたもの（MIT。NOTICE を参照）。
// 台紙に CRITICAL の帯。描画エラーの回復（ErrorBoundary）で使う。
import { Component, type ReactNode } from 'react';
import { OctagonAlert } from 'lucide-react';
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

/** 子の描画で例外が起きたら回復用のメッセージを出す。「クリアして再表示」で State を初期化して描画し直す。 */
export class ErrorBoundary extends Component<{ children: ReactNode; onReset(): void }, { failed: boolean }> {
  override state = { failed: false };
  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }
  override render() {
    if (!this.state.failed) return this.props.children;
    return (
      <Alert title="表示中にエラーが発生しました" data-testid="render-error">
        <p>取り込んだデータに表示できない値が含まれている可能性があります。結果をクリアして再表示してください（ファイル内容は外部に送信されません）。</p>
        <Button onClick={() => { this.props.onReset(); this.setState({ failed: false }); }} data-testid="render-error-reset">クリアして再表示</Button>
      </Alert>
    );
  }
}

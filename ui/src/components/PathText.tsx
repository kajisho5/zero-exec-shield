// パスの組み方（設計書 §6）: ディレクトリを鉛筆、ファイル名を墨の 500 で。等幅。
// パスは信頼できない文字列。制御文字・双方向制御文字は visiblePath() で目に見える目印にし、<bdi dir="ltr"> で
// 周りの文字列から双方向の並びを切り離す（パス内の RTL 文字が隣の UI 文言や行の並びを入れ替えないように）。
import { cn } from '@/lib/utils';
import { visiblePath } from '@/lib/visiblePath';

export function PathText({ path, className, wrap }: { path: string; className?: string; wrap?: boolean }) {
  const shown = visiblePath(path);
  const i = shown.lastIndexOf('/');
  const dir = i >= 0 ? shown.slice(0, i + 1) : '';
  const file = i >= 0 ? shown.slice(i + 1) : shown;
  return (
    <bdi dir="ltr" className={cn('font-mono', wrap ? 'block wrap-anywhere' : 'block truncate', className)}>
      {dir && <span className="text-muted-foreground">{dir}</span>}
      <span className="font-medium text-foreground">{file}</span>
    </bdi>
  );
}

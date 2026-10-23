// パスの組み方（設計書 §6）: ディレクトリを鉛筆、ファイル名を墨の 500 で。等幅。
import { cn } from '@/lib/utils';

export function PathText({ path, className, wrap }: { path: string; className?: string; wrap?: boolean }) {
  const i = path.lastIndexOf('/');
  const dir = i >= 0 ? path.slice(0, i + 1) : '';
  const file = i >= 0 ? path.slice(i + 1) : path;
  return (
    <span className={cn('font-mono', wrap ? 'wrap-anywhere' : 'block truncate', className)}>
      {dir && <span className="text-muted-foreground">{dir}</span>}
      <span className="font-medium text-foreground">{file}</span>
    </span>
  );
}

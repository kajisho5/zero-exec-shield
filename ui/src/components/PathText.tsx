// How paths are set (design doc §6): directories in pencil, the file name in ink at 500. Monospace.
// Paths are untrusted strings. Control characters and bidi control characters become visible markers via visiblePath(), and <bdi dir="ltr">
// isolates the bidi ordering from the surrounding text (so RTL characters in a path do not reorder the adjacent UI text or the row).
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

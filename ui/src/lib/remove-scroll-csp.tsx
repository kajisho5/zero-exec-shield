// react-remove-scroll の CSP 互換モジュール（vite.config.ts の resolve.alias で差し替える）。
//
// 本家は react-style-singleton で実行時に <style> を差し込んでスクロールをロックする。この UI の CSP は
// style-src にビルド時の CSS のハッシュ 1 つだけを許可するので、実行時の <style> はブロックされ、
// securitypolicyviolation が出る（設計書 §4.2）。ここでは同じ API（Radix が渡す props）を受け取り、
// ロックは CSSOM（element.style）で行う。CSSOM での書き込みは CSP の対象外。
//
// Radix が使うのは <RemoveScroll as={Slot} allowPinchZoom shards enabled> だけ。shards / allowPinchZoom の
// 「ロック中でもスクロールできる領域」は、body の overflow を止める方式では不要（中の要素は普通にスクロールする）。
import { forwardRef, useEffect, type ElementType, type ReactNode } from 'react';

let locks = 0;
let saved: { overflow: string; paddingRight: string } | null = null;

function lock() {
  if (locks++ > 0) return;
  const body = document.body;
  // スクロールバーが消える分だけ右に余白を足し、背面の配置がずれないようにする
  const gap = window.innerWidth - document.documentElement.clientWidth;
  saved = { overflow: body.style.overflow, paddingRight: body.style.paddingRight };
  body.style.overflow = 'hidden';
  if (gap > 0) body.style.paddingRight = `${gap}px`;
  body.setAttribute('data-scroll-locked', '');
}

function unlock() {
  if (--locks > 0) return;
  const body = document.body;
  if (saved) {
    body.style.overflow = saved.overflow;
    body.style.paddingRight = saved.paddingRight;
  }
  saved = null;
  body.removeAttribute('data-scroll-locked');
}

interface Props {
  as?: ElementType;
  children?: ReactNode;
  enabled?: boolean;
  className?: string;
  // 本家の props。受け取って捨てる（DOM に流さない）
  allowPinchZoom?: boolean;
  shards?: unknown;
  removeScrollBar?: boolean;
  inert?: boolean;
  noIsolation?: boolean;
  noRelative?: boolean;
  gapMode?: string;
  forwardProps?: boolean;
  lockRef?: unknown;
  sideCar?: unknown;
  [key: string]: unknown;
}

export const RemoveScroll = forwardRef<HTMLElement, Props>(function RemoveScroll(props, ref) {
  const {
    as, children, enabled = true,
    allowPinchZoom: _a, shards: _s, removeScrollBar: _r, inert: _i, noIsolation: _n, noRelative: _nr, gapMode: _g, forwardProps: _f, lockRef: _l, sideCar: _sc,
    ...rest
  } = props;
  const Comp = (as ?? 'div') as ElementType;
  useEffect(() => {
    if (!enabled) return;
    lock();
    return unlock;
  }, [enabled]);
  return <Comp ref={ref} {...rest}>{children}</Comp>;
});

export default RemoveScroll;

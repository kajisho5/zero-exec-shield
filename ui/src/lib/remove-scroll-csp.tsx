// CSP-compatible module of react-remove-scroll (swapped in by resolve.alias in vite.config.ts).
//
// The original locks scrolling by injecting <style> at runtime with react-style-singleton. The CSP of this UI
// allows only the one hash of the build-time CSS in style-src, so a runtime <style> is blocked and
// securitypolicyviolation fires (design doc §4.2). This module accepts the same API (the props Radix passes)
// and locks via CSSOM (element.style). Writes through CSSOM are not subject to CSP.
//
// Radix only uses <RemoveScroll as={Slot} allowPinchZoom shards enabled>. The "areas that can scroll even while locked"
// of shards / allowPinchZoom are unnecessary with the approach of stopping body overflow (elements inside scroll normally).
import { forwardRef, useEffect, type ElementType, type ReactNode } from 'react';

let locks = 0;
let saved: { overflow: string; paddingRight: string } | null = null;

function lock() {
  if (locks++ > 0) return;
  const body = document.body;
  // Add padding on the right for the width of the vanishing scrollbar, so the background layout does not shift
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
  // Props of the original. Accepted and discarded (not passed on to the DOM)
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

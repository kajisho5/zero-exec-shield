import { createContext, useContext, useReducer, type Dispatch, type ReactNode } from 'react';
import { initialState, reducer, type Action, type ScanState } from './reducer';

const Ctx = createContext<{ state: ScanState; dispatch: Dispatch<Action> } | null>(null);

export function ScanProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState);
  return <Ctx.Provider value={{ state, dispatch }}>{children}</Ctx.Provider>;
}

export function useScan() {
  const v = useContext(Ctx);
  if (!v) throw new Error('ScanProvider がありません');
  return v;
}

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { ToastProvider } from './components/ui/toast';
import { TooltipProvider } from './components/ui/tooltip';
import { applyTheme } from './hooks/useTheme';
import './styles/index.css';

// 描画の前にテーマのクラスを付ける（別のインラインスクリプトは CSP のハッシュが増えるので作らない）
applyTheme();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <TooltipProvider>
      <ToastProvider>
        <App />
      </ToastProvider>
    </TooltipProvider>
  </StrictMode>,
);

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { ToastProvider } from './components/ui/toast';
import { TooltipProvider } from './components/ui/tooltip';
import { applyTheme } from './hooks/useTheme';
import { applyLang } from './i18n';
import './styles/index.css';

// Set the theme class before rendering (no separate inline script, since that would add another CSP hash)
applyTheme();
applyLang();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <TooltipProvider>
      <ToastProvider>
        <App />
      </ToastProvider>
    </TooltipProvider>
  </StrictMode>,
);

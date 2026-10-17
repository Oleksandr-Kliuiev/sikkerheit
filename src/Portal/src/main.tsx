import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router';
import { ApiError } from './api/client';
import { Root } from './App';
import { I18nProvider } from './i18n/i18n';
import './styles.css';
import './styles/forms-tables.css';
import './styles/dialogs.css';
import './styles/workflows.css';
import './styles/template-library.css';

/**
 * An expired session anywhere sends the person back to sign-in: the session query is checked again. Its own 401
 * is the sign-in state itself and must not trigger another check.
 */
function onError(error: unknown, key?: readonly unknown[]) {
  if (error instanceof ApiError && error.status === 401 && key?.[0] !== 'me') {
    void client.invalidateQueries({ queryKey: ['me'] });
  }
}

const client: QueryClient = new QueryClient({
  queryCache: new QueryCache({ onError: (error, query) => onError(error, query.queryKey) }),
  mutationCache: new MutationCache({ onError: (error) => onError(error) }),
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: (count, error) => !(error instanceof ApiError && error.status >= 400 && error.status < 500) && count < 2,
      refetchOnWindowFocus: true,
    },
  },
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={client}>
      <I18nProvider>
        <BrowserRouter>
          <Root />
        </BrowserRouter>
      </I18nProvider>
    </QueryClientProvider>
  </StrictMode>,
);

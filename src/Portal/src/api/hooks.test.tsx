import type { ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { useFindings } from './hooks';

// Server identity comes from the cookie; the staff ID only partitions the browser query cache.
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it('does not reuse another session user’s My tasks cache or send that ID as a query parameter', async () => {
  const fetch = vi.fn(async (path: string) => Response.json({ items: [{ title: path }], nextCursor: null }));
  vi.stubGlobal('fetch', fetch);
  const client = new QueryClient({ defaultOptions: { queries: { staleTime: Infinity, retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  const { result, rerender } = renderHook(({ staffId }) => useFindings(null, { assignedTo: 'me' }, 'en', staffId),
    { wrapper, initialProps: { staffId: 'first-user' } });
  await waitFor(() => expect(result.current.isSuccess).toBe(true));
  expect(fetch).toHaveBeenCalledTimes(1);
  rerender({ staffId: 'second-user' });
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
  expect(fetch.mock.calls.every(([path]) => path.includes('assignedTo=me') && !path.includes('user'))).toBe(true);
});

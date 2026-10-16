import type { Problem } from './types';

/** A Problem answer of the API (05 «API портала»): status and the closed code. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly detail?: string,
  ) {
    super(detail ?? code);
  }
}

const session = { csrf: '', language: 'nb' };

export function setCsrfToken(token: string): void {
  session.csrf = token;
}

export function setApiLanguage(language: string): void {
  session.language = language;
}

export interface ApiResult<T> {
  data: T;
  etag: string | null;
  contentLanguage: string | null;
}

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH';
  body?: unknown;
  ifMatch?: string | null;
}

/** Same-origin JSON request with the session cookie; changes carry X-CSRF-Token (04 «Вход сотрудников и роли»). */
export async function request<T>(path: string, options: RequestOptions = {}): Promise<ApiResult<T>> {
  const method = options.method ?? 'GET';
  const headers: Record<string, string> = { Accept: 'application/json', 'Accept-Language': session.language };
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }
  if (method !== 'GET') {
    headers['X-CSRF-Token'] = session.csrf;
  }
  if (options.ifMatch) {
    headers['If-Match'] = options.ifMatch;
  }
  let response: Response;
  try {
    response = await fetch(path, {
      method,
      headers,
      credentials: 'same-origin',
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
  } catch {
    throw new ApiError(0, 'temporarily_unavailable');
  }
  if (!response.ok) {
    let problem: Partial<Problem> = {};
    try {
      problem = (await response.json()) as Partial<Problem>;
    } catch {
      // Not a Problem body (proxy or network error page).
    }
    throw new ApiError(response.status, problem.code ?? 'temporarily_unavailable', problem.detail);
  }
  const text = await response.text();
  return {
    data: (text ? JSON.parse(text) : undefined) as T,
    etag: response.headers.get('ETag'),
    contentLanguage: response.headers.get('Content-Language'),
  };
}

export async function get<T>(path: string): Promise<T> {
  return (await request<T>(path)).data;
}

export async function post<T>(path: string, body: unknown, ifMatch?: string | null): Promise<T> {
  return (await request<T>(path, { method: 'POST', body, ifMatch })).data;
}

export async function patch<T>(path: string, body: unknown, ifMatch?: string | null): Promise<T> {
  return (await request<T>(path, { method: 'PATCH', body, ifMatch })).data;
}

/** Query string from defined values; arrays become comma-separated filters. */
export function query(params: Record<string, string | number | readonly string[] | null | undefined>): string {
  const search = new URLSearchParams();
  for (const [name, value] of Object.entries(params)) {
    if (value === null || value === undefined || value === '' || (Array.isArray(value) && value.length === 0)) {
      continue;
    }
    search.set(name, Array.isArray(value) ? value.join(',') : String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : '';
}

export function idempotencyKey(): string {
  return crypto.randomUUID();
}

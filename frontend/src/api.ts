import type { Operation, Session } from './types.ts';

export class ApiError extends Error {
  status: number;
  code: string;
  operation?: Operation;
  constructor(message: string, status = 0, code = 'network_error', operation?: Operation) {
    super(message);
    this.status = status;
    this.code = code;
    this.operation = operation;
  }
}

interface Options { method?: string; body?: unknown; signal?: AbortSignal; silent401?: boolean; timeout?: number }

export class ApiClient {
  csrf = '';
  onUnauthorized: () => void = () => {};
  fetcher: typeof fetch;
  constructor(fetcher: typeof fetch = globalThis.fetch.bind(globalThis)) { this.fetcher = fetcher; }
  setSession(session: Session | null) { this.csrf = session?.csrf_token || ''; }
  async request<T>(path: string, options: Options = {}): Promise<T> {
    return this.requestAt<T>('/api/control' + path, options);
  }
  async requestAt<T>(path: string, options: Options = {}): Promise<T> {
    const method = options.method || 'GET';
    const headers = new Headers({ Accept: 'application/json' });
    let body: BodyInit | undefined;
    if (options.body instanceof Blob) {
      body = options.body;
      headers.set('Content-Type', 'application/zip');
    } else if (options.body !== undefined) {
      body = JSON.stringify(options.body);
      headers.set('Content-Type', 'application/json');
    }
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && this.csrf) headers.set('X-CSRF-Token', this.csrf);
    const timeout = AbortSignal.timeout(options.timeout || 45000);
    const signal = options.signal ? AbortSignal.any([options.signal, timeout]) : timeout;
    let response: Response;
    try {
      response = await this.fetcher(path, { method, headers, body, signal, credentials: 'same-origin', cache: 'no-store' });
    } catch (error) {
      if (options.signal?.aborted) throw error;
      throw new ApiError('Сервер не ответил. Проверьте соединение и повторите запрос.');
    }
    if (response.status === 204) return undefined as T;
    let data;
    try { data = await response.json(); }
    catch { throw new ApiError('Сервер вернул неожиданный ответ.', response.status, 'invalid_response'); }
    if (!response.ok) {
      if (response.status === 401 && !options.silent401) this.onUnauthorized();
      const message = typeof data?.detail === 'string' ? data.detail :
        response.status === 422 ? 'Проверьте введённые данные.' : 'Не удалось выполнить действие.';
      throw new ApiError(message, response.status, typeof data?.code === 'string' ? data.code : 'request_failed', data?.operation);
    }
    return data as T;
  }
}

export function errorMessage(error: unknown) {
  return error instanceof ApiError ? error.message : 'Не удалось выполнить действие. Попробуйте ещё раз.';
}

export interface ApiConfig {
  baseURL: string;
  defaultHeaders?: Record<string, string>;
  getAccessToken?: () => string | undefined;
}

function buildHeaders(config: ApiConfig, extra?: Record<string, string>): HeadersInit {
  const headers: Record<string, string> = { ...config.defaultHeaders, ...(extra || {}) };
  const token = config.getAccessToken?.();
  if (token) headers['Authorization'] = `Bearer ${token}`;
  return headers;
}

async function request<T>(
  config: ApiConfig,
  method: string,
  endpoint: string,
  body?: unknown,
  options?: { headers?: Record<string, string>; params?: Record<string, string | number | boolean | undefined> }
): Promise<T> {
  const baseURL = config.baseURL.replace(/\/$/, '');
  const url = new URL(`${baseURL}${endpoint}`);
  if (options?.params) {
    Object.entries(options.params).forEach(([k, v]) => {
      if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
    });
  }
  const res = await fetch(url.toString(), {
    method,
    headers: buildHeaders(config, options?.headers),
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    let errorMessage = `API ${method} ${endpoint} failed: ${res.status}`;
    try {
      const errorJson = JSON.parse(text);
      errorMessage = errorJson.message || errorJson.error || errorMessage;
    } catch {
      if (text) errorMessage += ` ${text}`;
    }
    const error = new Error(errorMessage) as any;
    error.status = res.status;
    error.response = { status: res.status, data: text };
    throw error;
  }
  return (await res.json()) as T;
}

/**
 * Factory function to create an API client with injectable configuration
 * Replaces class-based ApiClient with functional approach
 *
 * @param config - API configuration (baseURL, headers, token getter)
 * @returns Object with HTTP method functions (get, post, put, delete)
 *
 * @example
 * const api = createApiClient({ baseURL: 'https://api.example.com' });
 * const response = await api.get('/users');
 */
const createApiClient = (config: ApiConfig) => {
  return {
    get: <T,>(endpoint: string, options?: { headers?: Record<string, string>; params?: Record<string, string | number | boolean | undefined> }) =>
      request<T>(config, 'GET', endpoint, undefined, options),
    post: <T,>(endpoint: string, body?: unknown, options?: { headers?: Record<string, string>; params?: Record<string, string | number | boolean | undefined> }) =>
      request<T>(config, 'POST', endpoint, body, options),
    put: <T,>(endpoint: string, body?: unknown, options?: { headers?: Record<string, string>; params?: Record<string, string | number | boolean | undefined> }) =>
      request<T>(config, 'PUT', endpoint, body, options),
    delete: <T,>(endpoint: string, options?: { headers?: Record<string, string>; params?: Record<string, string | number | boolean | undefined> }) =>
      request<T>(config, 'DELETE', endpoint, undefined, options),
  };
};

export default createApiClient;


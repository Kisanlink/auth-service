export interface ApiConfig {
  baseURL: string;
  defaultHeaders?: Record<string, string>;
  getAccessToken?: () => string | undefined;
}

/**
 * Build headers for the request
 * 
 * Authentication priority (as per AAA service middleware):
 * 1. Authorization header (Bearer token) - preferred for service-to-service calls
 * 2. HTTP-only cookies (auth_token) - fallback for browser clients
 * 
 * The browser automatically sends cookies when credentials: 'include' is set in fetch.
 * The Authorization header takes precedence if both are present.
 */
function buildHeaders(config: ApiConfig, extra?: Record<string, string>): HeadersInit {
  const headers: Record<string, string> = { ...config.defaultHeaders, ...(extra || {}) };
  
  // Add Authorization header if token is available (backward compatibility)
  // Cookies will be sent automatically by browser when credentials: 'include' is set
  const token = config.getAccessToken?.();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
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

  // Build headers with Content-Type for JSON requests
  const headers = buildHeaders(config, options?.headers) as Record<string, string>;
  if (body !== undefined && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  const res = await fetch(url.toString(), {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    credentials: 'include', // REQUIRED: Include HTTP-only cookies (auth_token, refresh_token)
    // Cookies are automatically sent by browser when credentials: 'include' is set
    // Authorization header is still sent for backward compatibility (service-to-service)
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
 * **HTTP-Only Cookie Support:**
 * All requests automatically include credentials: 'include', which enables:
 * - Automatic sending of HTTP-only cookies (auth_token, refresh_token)
 * - Backward compatibility with Bearer token authentication via Authorization header
 * 
 * The AAA service middleware checks tokens in this order:
 * 1. Authorization header (Bearer token) - preferred for service-to-service
 * 2. Cookie (auth_token) - fallback for browser clients
 *
 * @param config - API configuration (baseURL, headers, token getter)
 * @returns Object with HTTP method functions (get, post, put, delete)
 *
 * @example
 * // Browser client - cookies are automatically sent
 * const api = createApiClient({ baseURL: 'https://api.example.com' });
 * const response = await api.get('/users');
 * 
 * @example
 * // Service-to-service - Bearer token in header
 * const api = createApiClient({ 
 *   baseURL: 'https://api.example.com',
 *   getAccessToken: () => localStorage.getItem('token')
 * });
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


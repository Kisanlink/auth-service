export interface ApiConfig {
  baseURL: string;
  defaultHeaders?: Record<string, string>;
  getAccessToken?: () => string | undefined;
}

// Removed ApiResponse interface - API already returns { success, data, message } format

export class ApiClient {
  private readonly baseURL: string;
  private readonly defaultHeaders: Record<string, string>;
  private readonly getAccessToken?: () => string | undefined;

  constructor(config: ApiConfig) {
    this.baseURL = config.baseURL.replace(/\/$/, '');
    this.defaultHeaders = config.defaultHeaders || {};
    this.getAccessToken = config.getAccessToken;
  }

  private buildHeaders(extra?: Record<string, string>): HeadersInit {
    const headers: Record<string, string> = { ...this.defaultHeaders, ...(extra || {}) };
    const token = this.getAccessToken?.();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
  }

  private async request<T>(method: string, endpoint: string, body?: unknown, options?: { headers?: Record<string, string>; params?: Record<string, string | number | boolean | undefined> }): Promise<T> {
    const url = new URL(`${this.baseURL}${endpoint}`);
    if (options?.params) {
      Object.entries(options.params).forEach(([k, v]) => {
        if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
      });
    }
    const res = await fetch(url.toString(), {
      method,
      headers: this.buildHeaders(options?.headers),
      body: body !== undefined ? JSON.stringify(body) : undefined
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

  get<T>(endpoint: string, options?: { headers?: Record<string, string>; params?: Record<string, string | number | boolean | undefined> }) {
    return this.request<T>('GET', endpoint, undefined, options);
  }
  post<T>(endpoint: string, body?: unknown, options?: { headers?: Record<string, string>; params?: Record<string, string | number | boolean | undefined> }) {
    return this.request<T>('POST', endpoint, body, options);
  }
  put<T>(endpoint: string, body?: unknown, options?: { headers?: Record<string, string>; params?: Record<string, string | number | boolean | undefined> }) {
    return this.request<T>('PUT', endpoint, body, options);
  }
  delete<T>(endpoint: string, options?: { headers?: Record<string, string>; params?: Record<string, string | number | boolean | undefined> }) {
    return this.request<T>('DELETE', endpoint, undefined, options);
  }
}



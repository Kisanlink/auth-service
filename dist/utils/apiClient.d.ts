export interface ApiConfig {
    baseURL: string;
    defaultHeaders?: Record<string, string>;
    getAccessToken?: () => string | undefined;
    /**
     * Enable cookie-based authentication.
     * When true, cookies are sent with cross-origin requests (credentials: 'include').
     * Required for browser clients using HTTP-only cookie authentication.
     *
     * @default false
     *
     * @example
     * // Browser client with cookie auth
     * const apiClient = createApiClient({
     *   baseURL: 'https://api.example.com',
     *   withCredentials: true,
     * });
     *
     * @see https://developer.mozilla.org/en-US/docs/Web/API/fetch#credentials
     */
    withCredentials?: boolean;
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
declare const createApiClient: (config: ApiConfig) => {
    get: <T>(endpoint: string, options?: {
        headers?: Record<string, string>;
        params?: Record<string, string | number | boolean | undefined>;
    }) => Promise<T>;
    post: <T>(endpoint: string, body?: unknown, options?: {
        headers?: Record<string, string>;
        params?: Record<string, string | number | boolean | undefined>;
    }) => Promise<T>;
    put: <T>(endpoint: string, body?: unknown, options?: {
        headers?: Record<string, string>;
        params?: Record<string, string | number | boolean | undefined>;
    }) => Promise<T>;
    delete: <T>(endpoint: string, options?: {
        headers?: Record<string, string>;
        params?: Record<string, string | number | boolean | undefined>;
    }) => Promise<T>;
};
export default createApiClient;

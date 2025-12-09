export interface ApiConfig {
    baseURL: string;
    defaultHeaders?: Record<string, string>;
    getAccessToken?: () => string | undefined;
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
    post: <T_1>(endpoint: string, body?: unknown, options?: {
        headers?: Record<string, string>;
        params?: Record<string, string | number | boolean | undefined>;
    }) => Promise<T_1>;
    put: <T_2>(endpoint: string, body?: unknown, options?: {
        headers?: Record<string, string>;
        params?: Record<string, string | number | boolean | undefined>;
    }) => Promise<T_2>;
    delete: <T_3>(endpoint: string, options?: {
        headers?: Record<string, string>;
        params?: Record<string, string | number | boolean | undefined>;
    }) => Promise<T_3>;
};
export default createApiClient;

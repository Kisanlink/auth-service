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
function buildHeaders(config, extra) {
    const headers = { ...config.defaultHeaders, ...(extra || {}) };
    // Add Authorization header if token is available (backward compatibility)
    // Cookies will be sent automatically by browser when credentials: 'include' is set
    const token = config.getAccessToken?.();
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }
    return headers;
}
async function request(config, method, endpoint, body, options) {
    const baseURL = config.baseURL.replace(/\/$/, '');
    const url = new URL(`${baseURL}${endpoint}`);
    if (options?.params) {
        Object.entries(options.params).forEach(([k, v]) => {
            if (v !== undefined && v !== null)
                url.searchParams.set(k, String(v));
        });
    }
    // Build headers with Content-Type for JSON requests
    const headers = buildHeaders(config, options?.headers);
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
        }
        catch {
            if (text)
                errorMessage += ` ${text}`;
        }
        const error = new Error(errorMessage);
        error.status = res.status;
        error.response = { status: res.status, data: text };
        throw error;
    }
    return (await res.json());
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
const createApiClient = (config) => {
    return {
        get: (endpoint, options) => request(config, 'GET', endpoint, undefined, options),
        post: (endpoint, body, options) => request(config, 'POST', endpoint, body, options),
        put: (endpoint, body, options) => request(config, 'PUT', endpoint, body, options),
        delete: (endpoint, options) => request(config, 'DELETE', endpoint, undefined, options),
    };
};
export default createApiClient;

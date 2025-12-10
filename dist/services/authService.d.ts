import createApiClient from '../utils/apiClient';
import { AuthLoginResponse, LoginRequest, PermissionEvaluationRequest, PermissionEvaluationResult, RefreshRequest } from '../types';
/**
 * Factory function to create an auth service with injectable API client.
 *
 * ## Cookie-Based Authentication
 *
 * When the API client is configured with `withCredentials: true`, the auth endpoints
 * support HTTP-only cookie-based authentication:
 *
 * - **Login**: Sets `auth_token` (1h) and `refresh_token` (7d) cookies via Set-Cookie headers
 * - **Refresh**: Updates both cookies with new tokens
 * - **Logout**: Clears both cookies by setting Max-Age=-1
 *
 * Cookie attributes vary by environment:
 * - Production: `HttpOnly; Secure; SameSite=None`
 * - Development with CORS: `HttpOnly; Secure; SameSite=None`
 * - Local: `HttpOnly; SameSite=Lax`
 *
 * @param apiClient - API client instance (configure with `withCredentials: true` for cookies)
 * @returns Auth service object with all authentication methods
 *
 * @example
 * // Bearer token authentication (default)
 * const apiClient = createApiClient({
 *   baseURL: 'https://api.example.com',
 *   getAccessToken: () => store.getState().auth.token,
 * });
 * const authService = createAuthService(apiClient);
 *
 * @example
 * // Cookie-based authentication (browser clients)
 * const apiClient = createApiClient({
 *   baseURL: 'https://api.example.com',
 *   withCredentials: true,  // Enable cookies
 * });
 * const authService = createAuthService(apiClient);
 *
 * // Login - cookies set automatically by browser
 * await authService.login({
 *   country_code: '+91',
 *   phone_number: '9876543210',
 *   password: 'password'
 * });
 *
 * // Subsequent requests use cookies automatically
 * // Logout - cookies cleared by server
 * await authService.logout();
 */
declare const createAuthService: (apiClient: ReturnType<typeof createApiClient>) => {
    /**
     * Authenticate user with phone number and password.
     *
     * ## Cookie Behavior
     * When `withCredentials: true`, the response includes Set-Cookie headers:
     * - `auth_token`: Access token (expires in 1 hour)
     * - `refresh_token`: Refresh token (expires in 7 days)
     *
     * Both cookies are HttpOnly and cannot be accessed via JavaScript.
     *
     * @param payload - Login credentials
     * @returns Authentication response with tokens and user data
     */
    login: (payload: LoginRequest) => Promise<AuthLoginResponse>;
    /**
     * Register a new user account.
     *
     * @param payload - Registration details
     * @returns User ID or full auth response depending on auto-login setting
     */
    register: (payload: {
        country_code: string;
        phone_number: string;
        password: string;
        name?: string;
    }) => Promise<AuthLoginResponse | {
        user_id: string;
    }>;
    /**
     * Logout and invalidate current session.
     *
     * ## Cookie Behavior
     * When `withCredentials: true`, the response clears cookies:
     * - Sets `auth_token` with Max-Age=-1
     * - Sets `refresh_token` with Max-Age=-1
     *
     * Always call this endpoint to properly clear server-side session.
     */
    logout: () => Promise<{}>;
    /**
     * Refresh access token using refresh token and MPIN.
     *
     * ## Cookie Behavior
     * When `withCredentials: true`:
     * - The `refresh_token` cookie is sent automatically
     * - Response updates both `auth_token` and `refresh_token` cookies
     * - Refresh tokens are rotated on each use for security
     *
     * @param payload - Refresh request with MPIN and optionally refresh_token
     * @returns New access and refresh tokens
     */
    refresh: (payload: RefreshRequest) => Promise<{
        access_token: string;
        refresh_token: string;
    }>;
    /**
     * Set MPIN for quick authentication.
     *
     * @param payload - MPIN and current password for verification
     */
    setMPIN: (payload: {
        mpin: string;
        password: string;
    }) => Promise<{}>;
    /**
     * Update existing MPIN.
     *
     * @param payload - Old MPIN (optional) and new MPIN
     */
    updateMPIN: (payload: {
        old_mpin?: string;
        new_mpin: string;
    }) => Promise<{}>;
    /**
     * Evaluate if user has a specific permission.
     *
     * @param payload - Permission evaluation request
     * @returns Whether permission is allowed and reasons
     */
    evaluatePermission: (payload: PermissionEvaluationRequest) => Promise<PermissionEvaluationResult>;
};
export default createAuthService;

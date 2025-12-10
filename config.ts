export interface AuthServiceConfig {
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
   * const aaaService = createAAAService({
   *   baseURL: 'https://api.example.com',
   *   withCredentials: true,
   * });
   */
  withCredentials?: boolean;
}

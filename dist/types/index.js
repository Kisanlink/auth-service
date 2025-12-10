/**
 * Cookie names used by the AAA service
 */
export const COOKIE_NAMES = {
    /** Access token cookie name */
    AUTH_TOKEN: 'auth_token',
    /** Refresh token cookie name */
    REFRESH_TOKEN: 'refresh_token',
};
/**
 * Default cookie configuration values
 */
export const COOKIE_DEFAULTS = {
    /** Access token expiry in seconds (1 hour) */
    AUTH_TOKEN_MAX_AGE: 3600,
    /** Refresh token expiry in seconds (7 days) */
    REFRESH_TOKEN_MAX_AGE: 604800,
};

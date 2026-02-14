export interface UserRoleRef {
    id: string;
    role: {
        id: string;
        name: string;
    };
}
export interface UserData {
    id: string;
    name?: string;
    phone_number?: string;
    roles: UserRoleRef[];
    must_change_password?: boolean;
}
export interface ChangePasswordRequest {
    old_password: string;
    new_password: string;
}
export interface ChangePasswordResponse {
    success: boolean;
    message: string;
}
export interface LoginRequest {
    country_code?: string;
    phone_number: string;
    password: string;
}
export interface AuthTokens {
    access_token: string;
    refresh_token: string;
}
export interface AuthLoginResponse {
    access_token: string;
    refresh_token: string;
    token_type?: 'Bearer';
    expires_in?: number;
    user: UserData;
    permissions?: string[];
    /** Cookie configuration hints (informational, actual cookies set via Set-Cookie header) */
    cookie_config?: CookieConfig;
}
export interface RefreshRequest {
    mpin: string;
    refresh_token: string;
}
export interface PermissionEvaluationRequest {
    user_id: string;
    permission: string;
    context?: Record<string, unknown>;
}
export interface PermissionEvaluationResult {
    allowed: boolean;
    reasons?: string[];
}
/**
 * Consent details for KYC/Aadhaar verification
 */
export interface KYCConsent {
    purpose: string;
    timestamp: string;
    version: string;
}
/**
 * Request payload for generating Aadhaar OTP
 */
export interface AadhaarOTPRequest {
    aadhaar_number: string;
    consent: KYCConsent;
    request_id?: string;
}
/**
 * Response from Aadhaar OTP generation
 */
export interface AadhaarOTPResponse {
    session_id: string;
    masked_aadhaar: string;
    otp_sent_to: string;
    expires_at: string;
    attempts_remaining: number;
    request_id: string;
}
/**
 * Request payload for verifying Aadhaar OTP
 */
export interface AadhaarVerifyRequest {
    session_id: string;
    otp: string;
    share_code?: string;
}
/**
 * Aadhaar address structure as per UIDAI specifications
 */
export interface AadhaarAddress {
    house: string;
    street: string;
    landmark: string;
    locality: string;
    vtc: string;
    district: string;
    state: string;
    pincode: string;
}
/**
 * KYC data returned after successful Aadhaar verification
 */
export interface KYCData {
    reference_id: string;
    name: string;
    dob: string;
    gender: 'M' | 'F' | 'O';
    address: AadhaarAddress;
    photo?: string;
}
/**
 * Response from Aadhaar OTP verification
 */
export interface AadhaarVerifyResponse {
    verification_id: string;
    status: 'verified' | 'failed';
    kyc_data?: KYCData;
    verified_at: string;
}
/**
 * Verification level details for a specific KYC type
 */
export interface VerificationLevel {
    status: 'verified' | 'pending' | 'not_initiated';
    verified_at?: string;
    expires_at?: string;
}
/**
 * All verification levels for a user
 */
export interface VerificationLevels {
    aadhaar?: VerificationLevel;
    pan?: VerificationLevel;
    bank_account?: VerificationLevel;
    [key: string]: VerificationLevel | undefined;
}
/**
 * Overall KYC status for a user
 */
export type KYCStatusType = 'not_initiated' | 'in_progress' | 'verified' | 'failed' | 'expired';
/**
 * Complete KYC status response
 */
export interface KYCStatus {
    user_id: string;
    kyc_status: KYCStatusType;
    verification_levels: VerificationLevels;
    next_action?: string;
    last_updated: string;
}
/**
 * KYC error response structure
 */
export interface KYCErrorResponse {
    error: {
        code: string;
        message: string;
        details?: unknown;
        retry_after?: number;
        attempts_remaining?: number;
    };
}
/**
 * Query parameters for listing services
 */
export interface ServiceListParams {
    organization_id?: string;
    is_active?: boolean;
    limit?: number;
    offset?: number;
}
/**
 * Request payload for creating a new service
 */
export interface CreateServiceRequest {
    name: string;
    api_key: string;
    organization_id: string;
    description?: string;
    metadata?: string;
}
/**
 * Request payload for updating an existing service
 */
export interface UpdateServiceRequest {
    name?: string;
    description?: string;
    api_key?: string;
    organization_id?: string;
    metadata?: string;
    is_active?: boolean;
}
/**
 * Service entity returned from API
 */
export interface ServiceData {
    id: string;
    name: string;
    description?: string;
    api_key?: string;
    organization_id?: string;
    metadata?: string;
    is_active: boolean;
    created_at: string;
    updated_at: string;
}
/**
 * Response from generate API key endpoint
 */
export interface GenerateApiKeyResponse {
    api_key: string;
}
/**
 * SameSite attribute for cookies
 * - 'Strict': Cookie only sent in first-party context
 * - 'Lax': Cookie sent with top-level navigations and GET from third-party
 * - 'None': Cookie sent in all contexts (requires Secure=true)
 */
export type CookieSameSite = 'Strict' | 'Lax' | 'None';
/**
 * Cookie configuration returned in auth responses
 * This is informational - actual cookies are set via Set-Cookie headers
 */
export interface CookieConfig {
    /** Max age for auth_token cookie in seconds (default: 3600) */
    auth_token_max_age: number;
    /** Max age for refresh_token cookie in seconds (default: 604800) */
    refresh_token_max_age: number;
    /** Whether cookies require HTTPS (true in production) */
    secure: boolean;
    /** SameSite attribute for cookies */
    same_site: CookieSameSite;
}
/**
 * Cookie names used by the AAA service
 */
export declare const COOKIE_NAMES: {
    /** Access token cookie name */
    readonly AUTH_TOKEN: "auth_token";
    /** Refresh token cookie name */
    readonly REFRESH_TOKEN: "refresh_token";
};
/**
 * Default cookie configuration values
 */
export declare const COOKIE_DEFAULTS: {
    /** Access token expiry in seconds (1 hour) */
    readonly AUTH_TOKEN_MAX_AGE: 3600;
    /** Refresh token expiry in seconds (7 days) */
    readonly REFRESH_TOKEN_MAX_AGE: 604800;
};

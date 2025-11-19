import createApiClient from '../utils/apiClient';
import { AuthLoginResponse, LoginRequest, PermissionEvaluationRequest, PermissionEvaluationResult, RefreshRequest } from '../types';
/**
 * Factory function to create an auth service with injectable API client
 *
 * @param apiClient - API client instance
 * @returns Auth service object with all authentication methods
 *
 * @example
 * const apiClient = createApiClient({ baseURL: 'https://api.example.com' });
 * const authService = createAuthService(apiClient);
 * await authService.login({ country_code: '+1', phone_number: '1234567890', password: 'pass' });
 */
declare const createAuthService: (apiClient: ReturnType<typeof createApiClient>) => {
    login: (payload: LoginRequest) => Promise<AuthLoginResponse>;
    register: (payload: {
        country_code: string;
        phone_number: string;
        password: string;
        name?: string;
    }) => Promise<AuthLoginResponse | {
        user_id: string;
    }>;
    logout: () => Promise<{}>;
    refresh: (payload: RefreshRequest) => Promise<{
        access_token: string;
        refresh_token: string;
    }>;
    setMPIN: (payload: {
        mpin: string;
        password: string;
    }) => Promise<{}>;
    updateMPIN: (payload: {
        old_mpin?: string;
        new_mpin: string;
    }) => Promise<{}>;
    evaluatePermission: (payload: PermissionEvaluationRequest) => Promise<PermissionEvaluationResult>;
};
export default createAuthService;

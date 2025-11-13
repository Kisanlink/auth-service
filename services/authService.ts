import createApiClient from '../utils/apiClient';
import {
  AuthLoginResponse,
  LoginRequest,
  PermissionEvaluationRequest,
  PermissionEvaluationResult,
  RefreshRequest
} from '../types';

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
const createAuthService = (apiClient: ReturnType<typeof createApiClient>) => {
  return {
    login: (payload: LoginRequest) =>
      apiClient.post<AuthLoginResponse>('/api/v1/auth/login', payload),

    register: (payload: { country_code: string; phone_number: string; password: string; name?: string }) =>
      apiClient.post<{ user_id: string } | AuthLoginResponse>('/api/v1/auth/register', payload),

    logout: () =>
      apiClient.post<{}>('/api/v1/auth/logout', {}),

    refresh: (payload: RefreshRequest) =>
      apiClient.post<{ access_token: string; refresh_token: string }>('/api/v1/auth/refresh', payload),

    setMPIN: (payload: { mpin: string; password: string }) =>
      apiClient.post<{}>('/api/v1/auth/set-mpin', payload),

    updateMPIN: (payload: { old_mpin?: string; new_mpin: string }) =>
      apiClient.post<{}>('/api/v1/auth/update-mpin', payload),

    evaluatePermission: (payload: PermissionEvaluationRequest) =>
      apiClient.post<PermissionEvaluationResult>('/api/v1/permissions/evaluate', payload),
  };
};

export default createAuthService;

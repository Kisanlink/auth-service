import { ApiClient } from '../utils/apiClient';
import { authServiceConfig } from '../config';
import {
  AuthLoginResponse,
  LoginRequest,
  PermissionEvaluationRequest,
  PermissionEvaluationResult,
  RefreshRequest
} from '../types';

export class AuthServiceClient {
  private readonly api: ApiClient;

  constructor(api: ApiClient = new ApiClient({
    baseURL: authServiceConfig.baseURL,
    defaultHeaders: authServiceConfig.defaultHeaders,
    getAccessToken: authServiceConfig.getAccessToken
  })) {
    this.api = api;
  }

  login(payload: LoginRequest) {
    return this.api.post<AuthLoginResponse>('/api/v1/auth/login', payload);
  }

  register(payload: { country_code: string; phone_number: string; password: string; name?: string }) {
    return this.api.post<{ user_id: string } | AuthLoginResponse>('/api/v1/auth/register', payload);
  }

  logout() {
    return this.api.post<{}>('/api/v1/auth/logout', {});
  }

  refresh(payload: RefreshRequest) {
    return this.api.post<{ access_token: string; refresh_token: string }>('/api/v1/auth/refresh', payload);
  }

  setMPIN(payload: { mpin: string }) {
    return this.api.post<{}>('/api/v1/auth/set-mpin', payload);
  }

  updateMPIN(payload: { old_mpin?: string; new_mpin: string }) {
    return this.api.post<{}>('/api/v1/auth/update-mpin', payload);
  }

  evaluatePermission(payload: PermissionEvaluationRequest) {
    return this.api.post<PermissionEvaluationResult>('/api/v1/permissions/evaluate', payload);
  }
}

export const authServiceClient = new AuthServiceClient();



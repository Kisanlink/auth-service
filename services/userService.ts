import { ApiClient } from '../utils/apiClient';
import { authServiceConfig } from '../config';

export interface UserListParams {
  limit?: number;
  offset?: number;
}

export interface UserSearchParams {
  q?: string;
  query?: string;
  limit?: number;
  offset?: number;
}

export interface CreateUserRequest {
  country_code: string;
  phone_number: string;
  password: string;
  name?: string;
  email?: string;
  username?: string;
  role_ids?: string[];
}

export interface UpdateUserRequest {
  name?: string;
  email?: string;
  phone_number?: string;
  country_code?: string;
}

export class UserServiceClient {
  private readonly api: ApiClient;

  constructor(api: ApiClient = new ApiClient({
    baseURL: authServiceConfig.baseURL,
    defaultHeaders: authServiceConfig.defaultHeaders,
    getAccessToken: authServiceConfig.getAccessToken
  })) {
    this.api = api;
  }

  // List users
  list(params?: UserListParams) {
    return this.api.get('/api/v1/users', { params: params as Record<string, string | number | boolean | undefined> });
  }

  // Create user
  create(payload: CreateUserRequest) {
    return this.api.post('/api/v1/users', payload);
  }

  // Get user by ID
  getById(userId: string) {
    return this.api.get(`/api/v1/users/${userId}`);
  }

  // Update user
  update(userId: string, payload: UpdateUserRequest) {
    return this.api.put(`/api/v1/users/${userId}`, payload);
  }

  // Delete user
  delete(userId: string) {
    return this.api.delete(`/api/v1/users/${userId}`);
  }

  // Search users
  search(params: UserSearchParams) {
    return this.api.get('/api/v1/users/search', { params: params as Record<string, string | number | boolean | undefined> });
  }

  // Evaluate user permission
  evaluate(userId: string, payload: { permission: string; context?: Record<string, unknown> }) {
    return this.api.post(`/api/v1/users/${userId}/evaluate`, payload);
  }

  // Get user roles
  getRoles(userId: string) {
    return this.api.get(`/api/v1/users/${userId}/roles`);
  }

  // Assign role to user
  assignRole(userId: string, roleId: string) {
    return this.api.post(`/api/v1/users/${userId}/roles/${roleId}`, {});
  }

  // Remove role from user
  removeRole(userId: string, roleId: string) {
    return this.api.delete(`/api/v1/users/${userId}/roles/${roleId}`);
  }

  // Validate user
  validate(userId: string) {
    return this.api.post(`/api/v1/users/${userId}/validate`, {});
  }
}

export const userServiceClient = new UserServiceClient();


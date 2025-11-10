import createApiClient from '../utils/apiClient';

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

const createUserService = (apiClient: ReturnType<typeof createApiClient>) => {
  return {
    list: (params?: UserListParams) =>
      apiClient.get('/api/v1/users', { params: params as Record<string, string | number | boolean | undefined> }),

    create: (payload: CreateUserRequest) =>
      apiClient.post('/api/v1/users', payload),

    getById: (userId: string) =>
      apiClient.get(`/api/v1/users/${userId}`),

    update: (userId: string, payload: UpdateUserRequest) =>
      apiClient.put(`/api/v1/users/${userId}`, payload),

    delete: (userId: string) =>
      apiClient.delete(`/api/v1/users/${userId}`),

    search: (params: UserSearchParams) =>
      apiClient.get('/api/v1/users/search', { params: params as Record<string, string | number | boolean | undefined> }),

    evaluate: (userId: string, payload: { permission: string; context?: Record<string, unknown> }) =>
      apiClient.post(`/api/v1/users/${userId}/evaluate`, payload),

    getRoles: (userId: string) =>
      apiClient.get(`/api/v1/users/${userId}/roles`),

    assignRole: (userId: string, roleId: string) =>
      apiClient.post(`/api/v1/users/${userId}/roles/${roleId}`, {}),

    removeRole: (userId: string, roleId: string) =>
      apiClient.delete(`/api/v1/users/${userId}/roles/${roleId}`),

    validate: (userId: string) =>
      apiClient.post(`/api/v1/users/${userId}/validate`, {}),
  };
};

export default createUserService;

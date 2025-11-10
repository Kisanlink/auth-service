import createApiClient from '../utils/apiClient';

export interface PermissionListParams {
  limit?: number;
  offset?: number;
  search?: string;
}

export interface CreatePermissionRequest {
  name: string;
  description?: string;
  action_id?: string;
  resource_id?: string;
}

export interface UpdatePermissionRequest {
  name?: string;
  description?: string;
  action_id?: string;
  resource_id?: string;
}

export interface EvaluatePermissionRequest {
  user_id: string;
  permission: string;
  context?: Record<string, unknown>;
}

const createPermissionService = (apiClient: ReturnType<typeof createApiClient>) => {
  return {
    list: (params?: PermissionListParams) =>
      apiClient.get('/api/v1/permissions', { params: params as Record<string, string | number | boolean | undefined> }),

    create: (payload: CreatePermissionRequest) =>
      apiClient.post('/api/v1/permissions', payload),

    getById: (permissionId: string) =>
      apiClient.get(`/api/v1/permissions/${permissionId}`),

    update: (permissionId: string, payload: UpdatePermissionRequest) =>
      apiClient.put(`/api/v1/permissions/${permissionId}`, payload),

    delete: (permissionId: string) =>
      apiClient.delete(`/api/v1/permissions/${permissionId}`),

    evaluate: (payload: EvaluatePermissionRequest) =>
      apiClient.post('/api/v1/permissions/evaluate', payload),
  };
};

export default createPermissionService;

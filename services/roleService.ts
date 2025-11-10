import createApiClient from '../utils/apiClient';

export interface RoleListParams {
  limit?: number;
  offset?: number;
  search?: string;
}

export interface CreateRoleRequest {
  name: string;
  description?: string;
  is_active?: boolean;
}

export interface UpdateRoleRequest {
  name?: string;
  description?: string;
  is_active?: boolean;
}

const createRoleService = (apiClient: ReturnType<typeof createApiClient>) => {
  return {
    list: (params?: RoleListParams) =>
      apiClient.get('/api/v1/roles', { params: params as Record<string, string | number | boolean | undefined> }),

    create: (payload: CreateRoleRequest) =>
      apiClient.post('/api/v1/roles', payload),

    getById: (roleId: string) =>
      apiClient.get(`/api/v1/roles/${roleId}`),

    update: (roleId: string, payload: UpdateRoleRequest) =>
      apiClient.put(`/api/v1/roles/${roleId}`, payload),

    delete: (roleId: string) =>
      apiClient.delete(`/api/v1/roles/${roleId}`),

    getPermissions: (roleId: string) =>
      apiClient.get(`/api/v1/roles/${roleId}/permissions`),

    assignPermissions: (roleId: string, permissionIds: string[]) =>
      apiClient.post(`/api/v1/roles/${roleId}/permissions`, { permission_ids: permissionIds }),

    removePermission: (roleId: string, permissionId: string) =>
      apiClient.delete(`/api/v1/roles/${roleId}/permissions/${permissionId}`),

    getResources: (roleId: string) =>
      apiClient.get(`/api/v1/roles/${roleId}/resources`),

    assignResource: (roleId: string, resourceId: string) =>
      apiClient.post(`/api/v1/roles/${roleId}/resources/${resourceId}`, {}),

    removeResource: (roleId: string, resourceId: string) =>
      apiClient.delete(`/api/v1/roles/${roleId}/resources/${resourceId}`),
  };
};

export default createRoleService;

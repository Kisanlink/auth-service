import { ApiClient } from '../utils/apiClient';
import { authServiceConfig } from '../config';

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

export class RoleServiceClient {
  private readonly api: ApiClient;

  constructor(api: ApiClient = new ApiClient({
    baseURL: authServiceConfig.baseURL,
    defaultHeaders: authServiceConfig.defaultHeaders,
    getAccessToken: authServiceConfig.getAccessToken
  })) {
    this.api = api;
  }

  // List roles
  list(params?: RoleListParams) {
    return this.api.get('/api/v1/roles', { params });
  }

  // Create role
  create(payload: CreateRoleRequest) {
    return this.api.post('/api/v1/roles', payload);
  }

  // Get role by ID
  getById(roleId: string) {
    return this.api.get(`/api/v1/roles/${roleId}`);
  }

  // Update role
  update(roleId: string, payload: UpdateRoleRequest) {
    return this.api.put(`/api/v1/roles/${roleId}`, payload);
  }

  // Delete role
  delete(roleId: string) {
    return this.api.delete(`/api/v1/roles/${roleId}`);
  }

  // Get role permissions
  getPermissions(roleId: string) {
    return this.api.get(`/api/v1/roles/${roleId}/permissions`);
  }

  // Assign permissions to role
  assignPermissions(roleId: string, permissionIds: string[]) {
    return this.api.post(`/api/v1/roles/${roleId}/permissions`, { permission_ids: permissionIds });
  }

  // Remove permission from role
  removePermission(roleId: string, permissionId: string) {
    return this.api.delete(`/api/v1/roles/${roleId}/permissions/${permissionId}`);
  }

  // Get role resources
  getResources(roleId: string) {
    return this.api.get(`/api/v1/roles/${roleId}/resources`);
  }

  // Assign resource to role
  assignResource(roleId: string, resourceId: string) {
    return this.api.post(`/api/v1/roles/${roleId}/resources/${resourceId}`, {});
  }

  // Remove resource from role
  removeResource(roleId: string, resourceId: string) {
    return this.api.delete(`/api/v1/roles/${roleId}/resources/${resourceId}`);
  }
}

export const roleServiceClient = new RoleServiceClient();


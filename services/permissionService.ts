import { ApiClient } from '../utils/apiClient';
import { authServiceConfig } from '../config';

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

export class PermissionServiceClient {
  private readonly api: ApiClient;

  constructor(api: ApiClient = new ApiClient({
    baseURL: authServiceConfig.baseURL,
    defaultHeaders: authServiceConfig.defaultHeaders,
    getAccessToken: authServiceConfig.getAccessToken
  })) {
    this.api = api;
  }

  // List permissions
  list(params?: PermissionListParams) {
    return this.api.get('/api/v1/permissions', { params });
  }

  // Create permission
  create(payload: CreatePermissionRequest) {
    return this.api.post('/api/v1/permissions', payload);
  }

  // Get permission by ID
  getById(permissionId: string) {
    return this.api.get(`/api/v1/permissions/${permissionId}`);
  }

  // Update permission
  update(permissionId: string, payload: UpdatePermissionRequest) {
    return this.api.put(`/api/v1/permissions/${permissionId}`, payload);
  }

  // Delete permission
  delete(permissionId: string) {
    return this.api.delete(`/api/v1/permissions/${permissionId}`);
  }

  // Evaluate permission
  evaluate(payload: EvaluatePermissionRequest) {
    return this.api.post('/api/v1/permissions/evaluate', payload);
  }
}

export const permissionServiceClient = new PermissionServiceClient();


import { ApiClient } from '../utils/apiClient';
import { authServiceConfig } from '../config';

export interface ResourceListParams {
  type?: string;
  parent_id?: string;
  owner_id?: string;
  is_active?: boolean;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface CreateResourceRequest {
  name: string;
  type: string;
  description?: string;
  parent_id?: string;
  owner_id?: string;
  is_active?: boolean;
}

export interface UpdateResourceRequest {
  name?: string;
  type?: string;
  description?: string;
  parent_id?: string;
  owner_id?: string;
  is_active?: boolean;
}

export class ResourceServiceClient {
  private readonly api: ApiClient;

  constructor(api: ApiClient = new ApiClient({
    baseURL: authServiceConfig.baseURL,
    defaultHeaders: authServiceConfig.defaultHeaders,
    getAccessToken: authServiceConfig.getAccessToken
  })) {
    this.api = api;
  }

  // List resources
  list(params?: ResourceListParams) {
    return this.api.get('/api/v1/resources', { params });
  }

  // Create resource
  create(payload: CreateResourceRequest) {
    return this.api.post('/api/v1/resources', payload);
  }

  // Get resource by ID
  getById(resourceId: string) {
    return this.api.get(`/api/v1/resources/${resourceId}`);
  }

  // Update resource
  update(resourceId: string, payload: UpdateResourceRequest) {
    return this.api.put(`/api/v1/resources/${resourceId}`, payload);
  }

  // Delete resource
  delete(resourceId: string) {
    return this.api.delete(`/api/v1/resources/${resourceId}`);
  }

  // Get resource children
  getChildren(resourceId: string) {
    return this.api.get(`/api/v1/resources/${resourceId}/children`);
  }

  // Get resource hierarchy
  getHierarchy(resourceId: string) {
    return this.api.get(`/api/v1/resources/${resourceId}/hierarchy`);
  }
}

export const resourceServiceClient = new ResourceServiceClient();


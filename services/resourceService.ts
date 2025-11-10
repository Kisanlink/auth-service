import createApiClient from '../utils/apiClient';

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

const createResourceService = (apiClient: ReturnType<typeof createApiClient>) => {
  return {
    list: (params?: ResourceListParams) =>
      apiClient.get('/api/v1/resources', { params: params as Record<string, string | number | boolean | undefined> }),

    create: (payload: CreateResourceRequest) =>
      apiClient.post('/api/v1/resources', payload),

    getById: (resourceId: string) =>
      apiClient.get(`/api/v1/resources/${resourceId}`),

    update: (resourceId: string, payload: UpdateResourceRequest) =>
      apiClient.put(`/api/v1/resources/${resourceId}`, payload),

    delete: (resourceId: string) =>
      apiClient.delete(`/api/v1/resources/${resourceId}`),

    getChildren: (resourceId: string) =>
      apiClient.get(`/api/v1/resources/${resourceId}/children`),

    getHierarchy: (resourceId: string) =>
      apiClient.get(`/api/v1/resources/${resourceId}/hierarchy`),
  };
};

export default createResourceService;

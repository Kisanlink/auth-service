import createApiClient from '../utils/apiClient';

export interface ActionListParams {
  limit?: number;
  offset?: number;
}

export interface CreateActionRequest {
  name: string;
  category: string;
  description?: string;
  service_id?: string;
  is_active?: boolean;
  is_static?: boolean;
  metadata?: string;
}

export interface UpdateActionRequest {
  name?: string;
  category?: string;
  description?: string;
  service_id?: string;
  is_active?: boolean;
  is_static?: boolean;
  metadata?: string;
}

const createActionService = (apiClient: ReturnType<typeof createApiClient>) => {
  return {
    list: (params?: ActionListParams) =>
      apiClient.get('/api/v1/actions', { params: params as Record<string, string | number | boolean | undefined> }),

    create: (payload: CreateActionRequest) =>
      apiClient.post('/api/v1/actions', payload),

    getById: (actionId: string) =>
      apiClient.get(`/api/v1/actions/${actionId}`),

    update: (actionId: string, payload: UpdateActionRequest) =>
      apiClient.put(`/api/v1/actions/${actionId}`, payload),

    delete: (actionId: string) =>
      apiClient.delete(`/api/v1/actions/${actionId}`),

    getByService: (serviceName: string, params?: ActionListParams) =>
      apiClient.get(`/api/v1/actions/service/${serviceName}`, { params: params as Record<string, string | number | boolean | undefined> }),
  };
};

export default createActionService;

import createApiClient from '../utils/apiClient';

export interface ServiceListParams {
  organization_id?: string;
  is_active?: boolean;
  limit?: number;
  offset?: number;
}

export interface CreateServiceRequest {
  name: string;
  api_key: string;
  organization_id: string;
  description?: string;
  metadata?: string;
}

export interface UpdateServiceRequest {
  name?: string;
  description?: string;
  api_key?: string;
  organization_id?: string;
  metadata?: string;
  is_active?: boolean;
}

const createServicesService = (apiClient: ReturnType<typeof createApiClient>) => {
  return {
    list: (params?: ServiceListParams) =>
      apiClient.get('/api/v1/services', { params: params as Record<string, string | number | boolean | undefined> }),

    create: (payload: CreateServiceRequest) =>
      apiClient.post('/api/v1/services', payload),

    getById: (serviceId: string) =>
      apiClient.get(`/api/v1/services/${serviceId}`),

    update: (serviceId: string, payload: UpdateServiceRequest) =>
      apiClient.put(`/api/v1/services/${serviceId}`, payload),

    delete: (serviceId: string) =>
      apiClient.delete(`/api/v1/services/${serviceId}`),

    generateApiKey: () =>
      apiClient.post('/api/v1/services/generate-api-key', {}),
  };
};

export default createServicesService;

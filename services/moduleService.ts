import createApiClient from '../utils/apiClient';

export interface RegisterModuleRequest {
  service_name: string;
  version: string;
  description?: string;
  endpoint?: string;
  health_check_endpoint?: string;
  metadata?: Record<string, unknown>;
}

const createModuleService = (apiClient: ReturnType<typeof createApiClient>) => {
  return {
    list: () =>
      apiClient.get('/api/v1/modules'),

    register: (payload: RegisterModuleRequest) =>
      apiClient.post('/api/v1/modules/register', payload),

    getByServiceName: (serviceName: string) =>
      apiClient.get(`/api/v1/modules/${serviceName}`),

    getHealth: (serviceName: string) =>
      apiClient.get(`/api/v1/modules/${serviceName}/health`),
  };
};

export default createModuleService;

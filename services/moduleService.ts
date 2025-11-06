import { ApiClient } from '../utils/apiClient';
import { authServiceConfig } from '../config';

export interface RegisterModuleRequest {
  service_name: string;
  version: string;
  description?: string;
  endpoint?: string;
  health_check_endpoint?: string;
  metadata?: Record<string, unknown>;
}

export class ModuleServiceClient {
  private readonly api: ApiClient;

  constructor(api: ApiClient = new ApiClient({
    baseURL: authServiceConfig.baseURL,
    defaultHeaders: authServiceConfig.defaultHeaders,
    getAccessToken: authServiceConfig.getAccessToken
  })) {
    this.api = api;
  }

  // List all registered modules
  list() {
    return this.api.get('/api/v1/modules');
  }

  // Register a module
  register(payload: RegisterModuleRequest) {
    return this.api.post('/api/v1/modules/register', payload);
  }

  // Get module by service name
  getByServiceName(serviceName: string) {
    return this.api.get(`/api/v1/modules/${serviceName}`);
  }

  // Get module health
  getHealth(serviceName: string) {
    return this.api.get(`/api/v1/modules/${serviceName}/health`);
  }
}

export const moduleServiceClient = new ModuleServiceClient();


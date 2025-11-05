import { ApiClient } from '../utils/apiClient';
import { authServiceConfig } from '../config';

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

export class ActionServiceClient {
  private readonly api: ApiClient;

  constructor(api: ApiClient = new ApiClient({
    baseURL: authServiceConfig.baseURL,
    defaultHeaders: authServiceConfig.defaultHeaders,
    getAccessToken: authServiceConfig.getAccessToken
  })) {
    this.api = api;
  }

  // List actions
  list(params?: ActionListParams) {
    return this.api.get('/api/v1/actions', { params });
  }

  // Create action
  create(payload: CreateActionRequest) {
    return this.api.post('/api/v1/actions', payload);
  }

  // Get action by ID
  getById(actionId: string) {
    return this.api.get(`/api/v1/actions/${actionId}`);
  }

  // Update action
  update(actionId: string, payload: UpdateActionRequest) {
    return this.api.put(`/api/v1/actions/${actionId}`, payload);
  }

  // Delete action
  delete(actionId: string) {
    return this.api.delete(`/api/v1/actions/${actionId}`);
  }

  // Get actions by service
  getByService(serviceName: string, params?: ActionListParams) {
    return this.api.get(`/api/v1/actions/service/${serviceName}`, { params });
  }
}

export const actionServiceClient = new ActionServiceClient();


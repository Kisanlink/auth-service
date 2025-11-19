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
declare const createActionService: (apiClient: ReturnType<typeof createApiClient>) => {
    list: (params?: ActionListParams) => Promise<unknown>;
    create: (payload: CreateActionRequest) => Promise<unknown>;
    getById: (actionId: string) => Promise<unknown>;
    update: (actionId: string, payload: UpdateActionRequest) => Promise<unknown>;
    delete: (actionId: string) => Promise<unknown>;
    getByService: (serviceName: string, params?: ActionListParams) => Promise<unknown>;
};
export default createActionService;

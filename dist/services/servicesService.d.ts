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
declare const createServicesService: (apiClient: ReturnType<typeof createApiClient>) => {
    list: (params?: ServiceListParams) => Promise<unknown>;
    create: (payload: CreateServiceRequest) => Promise<unknown>;
    getById: (serviceId: string) => Promise<unknown>;
    update: (serviceId: string, payload: UpdateServiceRequest) => Promise<unknown>;
    delete: (serviceId: string) => Promise<unknown>;
    generateApiKey: () => Promise<unknown>;
};
export default createServicesService;

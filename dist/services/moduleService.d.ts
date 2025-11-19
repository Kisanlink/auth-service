import createApiClient from '../utils/apiClient';
export interface RegisterModuleRequest {
    service_name: string;
    version: string;
    description?: string;
    endpoint?: string;
    health_check_endpoint?: string;
    metadata?: Record<string, unknown>;
}
declare const createModuleService: (apiClient: ReturnType<typeof createApiClient>) => {
    list: () => Promise<unknown>;
    register: (payload: RegisterModuleRequest) => Promise<unknown>;
    getByServiceName: (serviceName: string) => Promise<unknown>;
    getHealth: (serviceName: string) => Promise<unknown>;
};
export default createModuleService;

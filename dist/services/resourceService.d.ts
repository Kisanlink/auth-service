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
declare const createResourceService: (apiClient: ReturnType<typeof createApiClient>) => {
    list: (params?: ResourceListParams) => Promise<unknown>;
    create: (payload: CreateResourceRequest) => Promise<unknown>;
    getById: (resourceId: string) => Promise<unknown>;
    update: (resourceId: string, payload: UpdateResourceRequest) => Promise<unknown>;
    delete: (resourceId: string) => Promise<unknown>;
    getChildren: (resourceId: string) => Promise<unknown>;
    getHierarchy: (resourceId: string) => Promise<unknown>;
};
export default createResourceService;

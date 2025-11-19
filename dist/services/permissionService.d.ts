import createApiClient from '../utils/apiClient';
export interface PermissionListParams {
    limit?: number;
    offset?: number;
    search?: string;
}
export interface CreatePermissionRequest {
    name: string;
    description?: string;
    action_id?: string;
    resource_id?: string;
}
export interface UpdatePermissionRequest {
    name?: string;
    description?: string;
    action_id?: string;
    resource_id?: string;
}
export interface EvaluatePermissionRequest {
    user_id: string;
    permission: string;
    context?: Record<string, unknown>;
}
declare const createPermissionService: (apiClient: ReturnType<typeof createApiClient>) => {
    list: (params?: PermissionListParams) => Promise<unknown>;
    create: (payload: CreatePermissionRequest) => Promise<unknown>;
    getById: (permissionId: string) => Promise<unknown>;
    update: (permissionId: string, payload: UpdatePermissionRequest) => Promise<unknown>;
    delete: (permissionId: string) => Promise<unknown>;
    evaluate: (payload: EvaluatePermissionRequest) => Promise<unknown>;
};
export default createPermissionService;

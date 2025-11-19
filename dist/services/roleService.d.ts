import createApiClient from '../utils/apiClient';
export interface RoleListParams {
    limit?: number;
    offset?: number;
    search?: string;
}
export interface CreateRoleRequest {
    name: string;
    description?: string;
    is_active?: boolean;
}
export interface UpdateRoleRequest {
    name?: string;
    description?: string;
    is_active?: boolean;
}
declare const createRoleService: (apiClient: ReturnType<typeof createApiClient>) => {
    list: (params?: RoleListParams) => Promise<unknown>;
    create: (payload: CreateRoleRequest) => Promise<unknown>;
    getById: (roleId: string) => Promise<unknown>;
    update: (roleId: string, payload: UpdateRoleRequest) => Promise<unknown>;
    delete: (roleId: string) => Promise<unknown>;
    getPermissions: (roleId: string) => Promise<unknown>;
    assignPermissions: (roleId: string, permissionIds: string[]) => Promise<unknown>;
    removePermission: (roleId: string, permissionId: string) => Promise<unknown>;
    getResources: (roleId: string) => Promise<unknown>;
    assignResource: (roleId: string, resourceId: string) => Promise<unknown>;
    removeResource: (roleId: string, resourceId: string) => Promise<unknown>;
};
export default createRoleService;

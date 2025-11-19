import createApiClient from '../utils/apiClient';
export interface OrganizationListParams {
    limit?: number;
    offset?: number;
    type?: string;
    include_inactive?: boolean;
    search?: string;
}
export interface CreateOrganizationRequest {
    name: string;
    type: string;
    description?: string;
    parent_id?: string;
    metadata?: Record<string, unknown>;
}
export interface UpdateOrganizationRequest {
    name?: string;
    type?: string;
    description?: string;
    parent_id?: string;
    metadata?: Record<string, unknown>;
}
declare const createOrganizationService: (apiClient: ReturnType<typeof createApiClient>) => {
    list: (params?: OrganizationListParams) => Promise<unknown>;
    create: (payload: CreateOrganizationRequest) => Promise<unknown>;
    getById: (orgId: string) => Promise<unknown>;
    update: (orgId: string, payload: UpdateOrganizationRequest) => Promise<unknown>;
    delete: (orgId: string) => Promise<unknown>;
    activate: (orgId: string) => Promise<unknown>;
    deactivate: (orgId: string) => Promise<unknown>;
    getHierarchy: (orgId: string) => Promise<unknown>;
    getStats: (orgId: string) => Promise<unknown>;
    listGroups: (orgId: string, params?: {
        limit?: number;
        offset?: number;
    }) => Promise<unknown>;
    createGroup: (orgId: string, payload: {
        name: string;
        description?: string;
    }) => Promise<unknown>;
    getGroup: (orgId: string, groupId: string) => Promise<unknown>;
    updateGroup: (orgId: string, groupId: string, payload: {
        name?: string;
        description?: string;
    }) => Promise<unknown>;
    deleteGroup: (orgId: string, groupId: string) => Promise<unknown>;
    getGroupRoles: (orgId: string, groupId: string) => Promise<unknown>;
    assignRoleToGroup: (orgId: string, groupId: string, roleId: string) => Promise<unknown>;
    removeRoleFromGroup: (orgId: string, groupId: string, roleId: string) => Promise<unknown>;
    getGroupUsers: (orgId: string, groupId: string, params?: {
        limit?: number;
        offset?: number;
    }) => Promise<unknown>;
    addUserToGroup: (orgId: string, groupId: string, userId: string) => Promise<unknown>;
    removeUserFromGroup: (orgId: string, groupId: string, userId: string) => Promise<unknown>;
    getUserEffectiveRoles: (orgId: string, userId: string) => Promise<unknown>;
    getUserGroups: (orgId: string, userId: string) => Promise<unknown>;
};
export default createOrganizationService;

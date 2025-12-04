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

const createOrganizationService = (apiClient: ReturnType<typeof createApiClient>) => {
  return {
    list: (params?: OrganizationListParams) =>
      apiClient.get('/api/v1/organizations', { params: params as Record<string, string | number | boolean | undefined> }),

    create: (payload: CreateOrganizationRequest) =>
      apiClient.post('/api/v1/organizations', payload),

    getById: (orgId: string) =>
      apiClient.get(`/api/v1/organizations/${orgId}`),

    update: (orgId: string, payload: UpdateOrganizationRequest) =>
      apiClient.put(`/api/v1/organizations/${orgId}`, payload),

    delete: (orgId: string) =>
      apiClient.delete(`/api/v1/organizations/${orgId}`),

    activate: (orgId: string) =>
      apiClient.post(`/api/v1/organizations/${orgId}/activate`, {}),

    deactivate: (orgId: string) =>
      apiClient.post(`/api/v1/organizations/${orgId}/deactivate`, {}),

    getHierarchy: (orgId: string) =>
      apiClient.get(`/api/v1/organizations/${orgId}/hierarchy`),

    getStats: (orgId: string) =>
      apiClient.get(`/api/v1/organizations/${orgId}/stats`),

    listGroups: (orgId: string, params?: { limit?: number; offset?: number }) =>
      apiClient.get(`/api/v1/organizations/${orgId}/groups`, { params: params as Record<string, string | number | boolean | undefined> }),

    createGroup: (orgId: string, payload: { name: string; description?: string }) =>
      apiClient.post(`/api/v1/organizations/${orgId}/groups`, payload),

    getGroup: (orgId: string, groupId: string) =>
      apiClient.get(`/api/v1/organizations/${orgId}/groups/${groupId}`),

    updateGroup: (orgId: string, groupId: string, payload: { name?: string; description?: string }) =>
      apiClient.put(`/api/v1/organizations/${orgId}/groups/${groupId}`, payload),

    deleteGroup: (orgId: string, groupId: string) =>
      apiClient.delete(`/api/v1/organizations/${orgId}/groups/${groupId}`),

    getGroupRoles: (orgId: string, groupId: string) =>
      apiClient.get(`/api/v1/organizations/${orgId}/groups/${groupId}/roles`),

    assignRoleToGroup: (orgId: string, groupId: string, roleId: string) =>
      apiClient.post(`/api/v1/organizations/${orgId}/groups/${groupId}/roles`, { role_id: roleId }),

    removeRoleFromGroup: (orgId: string, groupId: string, roleId: string) =>
      apiClient.delete(`/api/v1/organizations/${orgId}/groups/${groupId}/roles/${roleId}`),

    getGroupUsers: (orgId: string, groupId: string, params?: { limit?: number; offset?: number }) =>
      apiClient.get(`/api/v1/organizations/${orgId}/groups/${groupId}/users`, { params: params as Record<string, string | number | boolean | undefined> }),

    addUserToGroup: (orgId: string, groupId: string, userId: string) =>
      apiClient.post(`/api/v1/organizations/${orgId}/groups/${groupId}/users`, { principal_id: userId, principal_type: 'user' }),

    removeUserFromGroup: (orgId: string, groupId: string, userId: string) =>
      apiClient.delete(`/api/v1/organizations/${orgId}/groups/${groupId}/users/${userId}`),

    getUserEffectiveRoles: (orgId: string, userId: string) =>
      apiClient.get(`/api/v1/organizations/${orgId}/users/${userId}/effective-roles`),

    getUserGroups: (orgId: string, userId: string) =>
      apiClient.get(`/api/v1/organizations/${orgId}/users/${userId}/groups`),
  };
};

export default createOrganizationService;

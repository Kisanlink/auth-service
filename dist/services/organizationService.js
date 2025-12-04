const createOrganizationService = (apiClient) => {
    return {
        list: (params) => apiClient.get('/api/v1/organizations', { params: params }),
        create: (payload) => apiClient.post('/api/v1/organizations', payload),
        getById: (orgId) => apiClient.get(`/api/v1/organizations/${orgId}`),
        update: (orgId, payload) => apiClient.put(`/api/v1/organizations/${orgId}`, payload),
        delete: (orgId) => apiClient.delete(`/api/v1/organizations/${orgId}`),
        activate: (orgId) => apiClient.post(`/api/v1/organizations/${orgId}/activate`, {}),
        deactivate: (orgId) => apiClient.post(`/api/v1/organizations/${orgId}/deactivate`, {}),
        getHierarchy: (orgId) => apiClient.get(`/api/v1/organizations/${orgId}/hierarchy`),
        getStats: (orgId) => apiClient.get(`/api/v1/organizations/${orgId}/stats`),
        listGroups: (orgId, params) => apiClient.get(`/api/v1/organizations/${orgId}/groups`, { params: params }),
        createGroup: (orgId, payload) => apiClient.post(`/api/v1/organizations/${orgId}/groups`, payload),
        getGroup: (orgId, groupId) => apiClient.get(`/api/v1/organizations/${orgId}/groups/${groupId}`),
        updateGroup: (orgId, groupId, payload) => apiClient.put(`/api/v1/organizations/${orgId}/groups/${groupId}`, payload),
        deleteGroup: (orgId, groupId) => apiClient.delete(`/api/v1/organizations/${orgId}/groups/${groupId}`),
        getGroupRoles: (orgId, groupId) => apiClient.get(`/api/v1/organizations/${orgId}/groups/${groupId}/roles`),
        assignRoleToGroup: (orgId, groupId, roleId) => apiClient.post(`/api/v1/organizations/${orgId}/groups/${groupId}/roles`, { role_id: roleId }),
        removeRoleFromGroup: (orgId, groupId, roleId) => apiClient.delete(`/api/v1/organizations/${orgId}/groups/${groupId}/roles/${roleId}`),
        getGroupUsers: (orgId, groupId, params) => apiClient.get(`/api/v1/organizations/${orgId}/groups/${groupId}/users`, { params: params }),
        addUserToGroup: (orgId, groupId, userId) => apiClient.post(`/api/v1/organizations/${orgId}/groups/${groupId}/users`, { principal_id: userId, principal_type: 'user' }),
        removeUserFromGroup: (orgId, groupId, userId) => apiClient.delete(`/api/v1/organizations/${orgId}/groups/${groupId}/users/${userId}`),
        getUserEffectiveRoles: (orgId, userId) => apiClient.get(`/api/v1/organizations/${orgId}/users/${userId}/effective-roles`),
        getUserGroups: (orgId, userId) => apiClient.get(`/api/v1/organizations/${orgId}/users/${userId}/groups`),
    };
};
export default createOrganizationService;

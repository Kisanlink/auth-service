const createRoleService = (apiClient) => {
    return {
        list: (params) => apiClient.get('/api/v1/roles', { params: params }),
        create: (payload) => apiClient.post('/api/v1/roles', payload),
        getById: (roleId) => apiClient.get(`/api/v1/roles/${roleId}`),
        update: (roleId, payload) => apiClient.put(`/api/v1/roles/${roleId}`, payload),
        delete: (roleId) => apiClient.delete(`/api/v1/roles/${roleId}`),
        getPermissions: (roleId) => apiClient.get(`/api/v1/roles/${roleId}/permissions`),
        assignPermissions: (roleId, permissionIds) => apiClient.post(`/api/v1/roles/${roleId}/permissions`, { permission_ids: permissionIds }),
        removePermission: (roleId, permissionId) => apiClient.delete(`/api/v1/roles/${roleId}/permissions/${permissionId}`),
        getResources: (roleId) => apiClient.get(`/api/v1/roles/${roleId}/resources`),
        assignResource: (roleId, resourceId) => apiClient.post(`/api/v1/roles/${roleId}/resources/${resourceId}`, {}),
        removeResource: (roleId, resourceId) => apiClient.delete(`/api/v1/roles/${roleId}/resources/${resourceId}`),
    };
};
export default createRoleService;

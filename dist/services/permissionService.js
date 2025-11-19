const createPermissionService = (apiClient) => {
    return {
        list: (params) => apiClient.get('/api/v1/permissions', { params: params }),
        create: (payload) => apiClient.post('/api/v1/permissions', payload),
        getById: (permissionId) => apiClient.get(`/api/v1/permissions/${permissionId}`),
        update: (permissionId, payload) => apiClient.put(`/api/v1/permissions/${permissionId}`, payload),
        delete: (permissionId) => apiClient.delete(`/api/v1/permissions/${permissionId}`),
        evaluate: (payload) => apiClient.post('/api/v1/permissions/evaluate', payload),
    };
};
export default createPermissionService;

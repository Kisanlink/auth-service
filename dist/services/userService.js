const createUserService = (apiClient) => {
    return {
        list: (params) => apiClient.get('/api/v1/users', { params: params }),
        create: (payload) => apiClient.post('/api/v1/users', payload),
        getById: (userId) => apiClient.get(`/api/v1/users/${userId}`),
        update: (userId, payload) => apiClient.put(`/api/v1/users/${userId}`, payload),
        delete: (userId) => apiClient.delete(`/api/v1/users/${userId}`),
        search: (params) => apiClient.get('/api/v1/users/search', { params: params }),
        evaluate: (userId, payload) => apiClient.post(`/api/v1/users/${userId}/evaluate`, payload),
        getRoles: (userId) => apiClient.get(`/api/v1/users/${userId}/roles`),
        assignRole: (userId, roleId) => apiClient.post(`/api/v1/users/${userId}/roles/${roleId}`, {}),
        removeRole: (userId, roleId) => apiClient.delete(`/api/v1/users/${userId}/roles/${roleId}`),
        validate: (userId) => apiClient.post(`/api/v1/users/${userId}/validate`, {}),
    };
};
export default createUserService;

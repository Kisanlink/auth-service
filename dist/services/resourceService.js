const createResourceService = (apiClient) => {
    return {
        list: (params) => apiClient.get('/api/v1/resources', { params: params }),
        create: (payload) => apiClient.post('/api/v1/resources', payload),
        getById: (resourceId) => apiClient.get(`/api/v1/resources/${resourceId}`),
        update: (resourceId, payload) => apiClient.put(`/api/v1/resources/${resourceId}`, payload),
        delete: (resourceId) => apiClient.delete(`/api/v1/resources/${resourceId}`),
        getChildren: (resourceId) => apiClient.get(`/api/v1/resources/${resourceId}/children`),
        getHierarchy: (resourceId) => apiClient.get(`/api/v1/resources/${resourceId}/hierarchy`),
    };
};
export default createResourceService;

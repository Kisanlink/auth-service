const createActionService = (apiClient) => {
    return {
        list: (params) => apiClient.get('/api/v1/actions', { params: params }),
        create: (payload) => apiClient.post('/api/v1/actions', payload),
        getById: (actionId) => apiClient.get(`/api/v1/actions/${actionId}`),
        update: (actionId, payload) => apiClient.put(`/api/v1/actions/${actionId}`, payload),
        delete: (actionId) => apiClient.delete(`/api/v1/actions/${actionId}`),
        getByService: (serviceName, params) => apiClient.get(`/api/v1/actions/service/${serviceName}`, { params: params }),
    };
};
export default createActionService;

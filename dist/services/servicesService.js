const createServicesService = (apiClient) => {
    return {
        list: (params) => apiClient.get('/api/v1/services', { params: params }),
        create: (payload) => apiClient.post('/api/v1/services', payload),
        getById: (serviceId) => apiClient.get(`/api/v1/services/${serviceId}`),
        update: (serviceId, payload) => apiClient.put(`/api/v1/services/${serviceId}`, payload),
        delete: (serviceId) => apiClient.delete(`/api/v1/services/${serviceId}`),
        generateApiKey: () => apiClient.post('/api/v1/services/generate-api-key', {}),
    };
};
export default createServicesService;

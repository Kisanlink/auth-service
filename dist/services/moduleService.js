const createModuleService = (apiClient) => {
    return {
        list: () => apiClient.get('/api/v1/modules'),
        register: (payload) => apiClient.post('/api/v1/modules/register', payload),
        getByServiceName: (serviceName) => apiClient.get(`/api/v1/modules/${serviceName}`),
        getHealth: (serviceName) => apiClient.get(`/api/v1/modules/${serviceName}/health`),
    };
};
export default createModuleService;

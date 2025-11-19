const createContactService = (apiClient) => {
    return {
        list: (params) => apiClient.get('/api/v1/contacts', { params: params }),
        create: (payload) => apiClient.post('/api/v1/contacts', payload),
        getById: (contactId) => apiClient.get(`/api/v1/contacts/${contactId}`),
        update: (contactId, payload) => apiClient.put(`/api/v1/contacts/${contactId}`, payload),
        delete: (contactId) => apiClient.delete(`/api/v1/contacts/${contactId}`),
        getByUser: (userId, params) => apiClient.get(`/api/v1/contacts/user/${userId}`, { params: params }),
    };
};
export default createContactService;

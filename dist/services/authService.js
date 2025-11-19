/**
 * Factory function to create an auth service with injectable API client
 *
 * @param apiClient - API client instance
 * @returns Auth service object with all authentication methods
 *
 * @example
 * const apiClient = createApiClient({ baseURL: 'https://api.example.com' });
 * const authService = createAuthService(apiClient);
 * await authService.login({ country_code: '+1', phone_number: '1234567890', password: 'pass' });
 */
const createAuthService = (apiClient) => {
    return {
        login: (payload) => apiClient.post('/api/v1/auth/login', payload),
        register: (payload) => apiClient.post('/api/v1/auth/register', payload),
        logout: () => apiClient.post('/api/v1/auth/logout', {}),
        refresh: (payload) => apiClient.post('/api/v1/auth/refresh', payload),
        setMPIN: (payload) => apiClient.post('/api/v1/auth/set-mpin', payload),
        updateMPIN: (payload) => apiClient.post('/api/v1/auth/update-mpin', payload),
        evaluatePermission: (payload) => apiClient.post('/api/v1/permissions/evaluate', payload),
    };
};
export default createAuthService;

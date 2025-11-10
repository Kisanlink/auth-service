import createApiClient from '../utils/apiClient';

export interface ContactListParams {
  limit?: number;
  offset?: number;
}

export interface CreateContactRequest {
  user_id: string;
  type: string;
  value: string;
  is_primary?: boolean;
  is_verified?: boolean;
  metadata?: Record<string, unknown>;
}

export interface UpdateContactRequest {
  type?: string;
  value?: string;
  is_primary?: boolean;
  is_verified?: boolean;
  metadata?: Record<string, unknown>;
}

const createContactService = (apiClient: ReturnType<typeof createApiClient>) => {
  return {
    list: (params?: ContactListParams) =>
      apiClient.get('/api/v1/contacts', { params: params as Record<string, string | number | boolean | undefined> }),

    create: (payload: CreateContactRequest) =>
      apiClient.post('/api/v1/contacts', payload),

    getById: (contactId: string) =>
      apiClient.get(`/api/v1/contacts/${contactId}`),

    update: (contactId: string, payload: UpdateContactRequest) =>
      apiClient.put(`/api/v1/contacts/${contactId}`, payload),

    delete: (contactId: string) =>
      apiClient.delete(`/api/v1/contacts/${contactId}`),

    getByUser: (userId: string, params?: ContactListParams) =>
      apiClient.get(`/api/v1/contacts/user/${userId}`, { params: params as Record<string, string | number | boolean | undefined> }),
  };
};

export default createContactService;

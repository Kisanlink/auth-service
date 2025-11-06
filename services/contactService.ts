import { ApiClient } from '../utils/apiClient';
import { authServiceConfig } from '../config';

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

export class ContactServiceClient {
  private readonly api: ApiClient;

  constructor(api: ApiClient = new ApiClient({
    baseURL: authServiceConfig.baseURL,
    defaultHeaders: authServiceConfig.defaultHeaders,
    getAccessToken: authServiceConfig.getAccessToken
  })) {
    this.api = api;
  }

  // List contacts
  list(params?: ContactListParams) {
    return this.api.get('/api/v1/contacts', { params });
  }

  // Create contact
  create(payload: CreateContactRequest) {
    return this.api.post('/api/v1/contacts', payload);
  }

  // Get contact by ID
  getById(contactId: string) {
    return this.api.get(`/api/v1/contacts/${contactId}`);
  }

  // Update contact
  update(contactId: string, payload: UpdateContactRequest) {
    return this.api.put(`/api/v1/contacts/${contactId}`, payload);
  }

  // Delete contact
  delete(contactId: string) {
    return this.api.delete(`/api/v1/contacts/${contactId}`);
  }

  // Get contacts by user
  getByUser(userId: string, params?: ContactListParams) {
    return this.api.get(`/api/v1/contacts/user/${userId}`, { params });
  }
}

export const contactServiceClient = new ContactServiceClient();


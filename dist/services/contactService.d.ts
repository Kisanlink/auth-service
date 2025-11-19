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
declare const createContactService: (apiClient: ReturnType<typeof createApiClient>) => {
    list: (params?: ContactListParams) => Promise<unknown>;
    create: (payload: CreateContactRequest) => Promise<unknown>;
    getById: (contactId: string) => Promise<unknown>;
    update: (contactId: string, payload: UpdateContactRequest) => Promise<unknown>;
    delete: (contactId: string) => Promise<unknown>;
    getByUser: (userId: string, params?: ContactListParams) => Promise<unknown>;
};
export default createContactService;

import createApiClient from '../utils/apiClient';
export interface UserListParams {
    limit?: number;
    offset?: number;
}
export interface UserSearchParams {
    q?: string;
    query?: string;
    limit?: number;
    offset?: number;
}
export interface CreateUserRequest {
    country_code: string;
    phone_number: string;
    password: string;
    name?: string;
    email?: string;
    username?: string;
    role_ids?: string[];
}
export interface UpdateUserRequest {
    name?: string;
    email?: string;
    phone_number?: string;
    country_code?: string;
}
declare const createUserService: (apiClient: ReturnType<typeof createApiClient>) => {
    list: (params?: UserListParams) => Promise<unknown>;
    create: (payload: CreateUserRequest) => Promise<unknown>;
    getById: (userId: string) => Promise<unknown>;
    update: (userId: string, payload: UpdateUserRequest) => Promise<unknown>;
    delete: (userId: string) => Promise<unknown>;
    search: (params: UserSearchParams) => Promise<unknown>;
    evaluate: (userId: string, payload: {
        permission: string;
        context?: Record<string, unknown>;
    }) => Promise<unknown>;
    getRoles: (userId: string) => Promise<unknown>;
    assignRole: (userId: string, roleId: string) => Promise<unknown>;
    removeRole: (userId: string, roleId: string) => Promise<unknown>;
    validate: (userId: string) => Promise<unknown>;
};
export default createUserService;

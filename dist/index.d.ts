export * from './config';
export * from './types';
export { default as createApiClient } from './utils/apiClient';
export { default as createAuthService } from './services/authService';
export { default as createUserService } from './services/userService';
export { default as createRoleService } from './services/roleService';
export { default as createPermissionService } from './services/permissionService';
export { default as createResourceService } from './services/resourceService';
export { default as createOrganizationService } from './services/organizationService';
export { default as createActionService } from './services/actionService';
export { default as createContactService } from './services/contactService';
export { default as createModuleService } from './services/moduleService';
export { default as createKYCService } from './services/kycService';
export { default as createServicesService } from './services/servicesService';
import { AuthServiceConfig } from './config';
declare const createAAAService: (config: AuthServiceConfig) => {
    auth: {
        login: (payload: import("./types").LoginRequest) => Promise<import("./types").AuthLoginResponse>;
        register: (payload: {
            country_code: string;
            phone_number: string;
            password: string;
            name?: string;
        }) => Promise<import("./types").AuthLoginResponse | {
            user_id: string;
        }>;
        logout: () => Promise<{}>;
        refresh: (payload: import("./types").RefreshRequest) => Promise<{
            access_token: string;
            refresh_token: string;
        }>;
        setMPIN: (payload: {
            mpin: string;
            password: string;
        }) => Promise<{}>;
        updateMPIN: (payload: {
            old_mpin?: string;
            new_mpin: string;
        }) => Promise<{}>;
        evaluatePermission: (payload: import("./types").PermissionEvaluationRequest) => Promise<import("./types").PermissionEvaluationResult>;
        changePassword: (payload: import("./types").ChangePasswordRequest) => Promise<import("./types").ChangePasswordResponse>;
    };
    users: {
        list: (params?: import("./services/userService").UserListParams) => Promise<unknown>;
        create: (payload: import("./services/userService").CreateUserRequest) => Promise<unknown>;
        getById: (userId: string) => Promise<unknown>;
        update: (userId: string, payload: import("./services/userService").UpdateUserRequest) => Promise<unknown>;
        delete: (userId: string) => Promise<unknown>;
        search: (params: import("./services/userService").UserSearchParams) => Promise<unknown>;
        evaluate: (userId: string, payload: {
            permission: string;
            context?: Record<string, unknown>;
        }) => Promise<unknown>;
        getRoles: (userId: string) => Promise<unknown>;
        assignRole: (userId: string, roleId: string) => Promise<unknown>;
        removeRole: (userId: string, roleId: string) => Promise<unknown>;
        validate: (userId: string) => Promise<unknown>;
    };
    roles: {
        list: (params?: import("./services/roleService").RoleListParams) => Promise<unknown>;
        create: (payload: import("./services/roleService").CreateRoleRequest) => Promise<unknown>;
        getById: (roleId: string) => Promise<unknown>;
        update: (roleId: string, payload: import("./services/roleService").UpdateRoleRequest) => Promise<unknown>;
        delete: (roleId: string) => Promise<unknown>;
        getPermissions: (roleId: string) => Promise<unknown>;
        assignPermissions: (roleId: string, permissionIds: string[]) => Promise<unknown>;
        removePermission: (roleId: string, permissionId: string) => Promise<unknown>;
        getResources: (roleId: string) => Promise<unknown>;
        assignResource: (roleId: string, resourceId: string) => Promise<unknown>;
        removeResource: (roleId: string, resourceId: string) => Promise<unknown>;
    };
    permissions: {
        list: (params?: import("./services/permissionService").PermissionListParams) => Promise<unknown>;
        create: (payload: import("./services/permissionService").CreatePermissionRequest) => Promise<unknown>;
        getById: (permissionId: string) => Promise<unknown>;
        update: (permissionId: string, payload: import("./services/permissionService").UpdatePermissionRequest) => Promise<unknown>;
        delete: (permissionId: string) => Promise<unknown>;
        evaluate: (payload: import("./services/permissionService").EvaluatePermissionRequest) => Promise<unknown>;
    };
    resources: {
        list: (params?: import("./services/resourceService").ResourceListParams) => Promise<unknown>;
        create: (payload: import("./services/resourceService").CreateResourceRequest) => Promise<unknown>;
        getById: (resourceId: string) => Promise<unknown>;
        update: (resourceId: string, payload: import("./services/resourceService").UpdateResourceRequest) => Promise<unknown>;
        delete: (resourceId: string) => Promise<unknown>;
        getChildren: (resourceId: string) => Promise<unknown>;
        getHierarchy: (resourceId: string) => Promise<unknown>;
    };
    organizations: {
        list: (params?: import("./services/organizationService").OrganizationListParams) => Promise<unknown>;
        create: (payload: import("./services/organizationService").CreateOrganizationRequest) => Promise<unknown>;
        getById: (orgId: string) => Promise<unknown>;
        update: (orgId: string, payload: import("./services/organizationService").UpdateOrganizationRequest) => Promise<unknown>;
        delete: (orgId: string) => Promise<unknown>;
        activate: (orgId: string) => Promise<unknown>;
        deactivate: (orgId: string) => Promise<unknown>;
        getHierarchy: (orgId: string) => Promise<unknown>;
        getStats: (orgId: string) => Promise<unknown>;
        listGroups: (orgId: string, params?: {
            limit?: number;
            offset?: number;
        }) => Promise<unknown>;
        createGroup: (orgId: string, payload: {
            name: string;
            description?: string;
        }) => Promise<unknown>;
        getGroup: (orgId: string, groupId: string) => Promise<unknown>;
        updateGroup: (orgId: string, groupId: string, payload: {
            name?: string;
            description?: string;
        }) => Promise<unknown>;
        deleteGroup: (orgId: string, groupId: string) => Promise<unknown>;
        getGroupRoles: (orgId: string, groupId: string) => Promise<unknown>;
        assignRoleToGroup: (orgId: string, groupId: string, roleId: string) => Promise<unknown>;
        removeRoleFromGroup: (orgId: string, groupId: string, roleId: string) => Promise<unknown>;
        getGroupUsers: (orgId: string, groupId: string, params?: {
            limit?: number;
            offset?: number;
        }) => Promise<unknown>;
        addUserToGroup: (orgId: string, groupId: string, userId: string) => Promise<unknown>;
        removeUserFromGroup: (orgId: string, groupId: string, userId: string) => Promise<unknown>;
        getUserEffectiveRoles: (orgId: string, userId: string) => Promise<unknown>;
        getUserGroups: (orgId: string, userId: string) => Promise<unknown>;
    };
    actions: {
        list: (params?: import("./services/actionService").ActionListParams) => Promise<unknown>;
        create: (payload: import("./services/actionService").CreateActionRequest) => Promise<unknown>;
        getById: (actionId: string) => Promise<unknown>;
        update: (actionId: string, payload: import("./services/actionService").UpdateActionRequest) => Promise<unknown>;
        delete: (actionId: string) => Promise<unknown>;
        getByService: (serviceName: string, params?: import("./services/actionService").ActionListParams) => Promise<unknown>;
    };
    contacts: {
        list: (params?: import("./services/contactService").ContactListParams) => Promise<unknown>;
        create: (payload: import("./services/contactService").CreateContactRequest) => Promise<unknown>;
        getById: (contactId: string) => Promise<unknown>;
        update: (contactId: string, payload: import("./services/contactService").UpdateContactRequest) => Promise<unknown>;
        delete: (contactId: string) => Promise<unknown>;
        getByUser: (userId: string, params?: import("./services/contactService").ContactListParams) => Promise<unknown>;
    };
    modules: {
        list: () => Promise<unknown>;
        register: (payload: import("./services/moduleService").RegisterModuleRequest) => Promise<unknown>;
        getByServiceName: (serviceName: string) => Promise<unknown>;
        getHealth: (serviceName: string) => Promise<unknown>;
    };
    kyc: {
        aadhaar: {
            generateOTP: (request: import("./types").AadhaarOTPRequest) => Promise<import("./types").AadhaarOTPResponse>;
            verifyOTP: (request: import("./types").AadhaarVerifyRequest) => Promise<import("./types").AadhaarVerifyResponse>;
        };
        status: {
            get: (userId: string) => Promise<import("./types").KYCStatus>;
        };
    };
    services: {
        list: (params?: import("./services/servicesService").ServiceListParams) => Promise<unknown>;
        create: (payload: import("./services/servicesService").CreateServiceRequest) => Promise<unknown>;
        getById: (serviceId: string) => Promise<unknown>;
        update: (serviceId: string, payload: import("./services/servicesService").UpdateServiceRequest) => Promise<unknown>;
        delete: (serviceId: string) => Promise<unknown>;
        generateApiKey: () => Promise<unknown>;
    };
};
export default createAAAService;

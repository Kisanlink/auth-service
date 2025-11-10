// Export all types
export * from './config';
export * from './types';

// Export API client
export { default as createApiClient } from './utils/apiClient';

// Export all services
export { default as createAuthService } from './services/authService';
export { default as createUserService } from './services/userService';
export { default as createRoleService } from './services/roleService';
export { default as createPermissionService } from './services/permissionService';
export { default as createResourceService } from './services/resourceService';
export { default as createOrganizationService } from './services/organizationService';
export { default as createActionService } from './services/actionService';
export { default as createContactService } from './services/contactService';
export { default as createModuleService } from './services/moduleService';

// Main AAAService factory function
import createApiClient from './utils/apiClient';
import createAuthService from './services/authService';
import createUserService from './services/userService';
import createRoleService from './services/roleService';
import createPermissionService from './services/permissionService';
import createResourceService from './services/resourceService';
import createOrganizationService from './services/organizationService';
import createActionService from './services/actionService';
import createContactService from './services/contactService';
import createModuleService from './services/moduleService';
import { AuthServiceConfig } from './config';

const createAAAService = (config: AuthServiceConfig) => {
  const apiClient = createApiClient({
    baseURL: config.baseURL,
    defaultHeaders: config.defaultHeaders,
    getAccessToken: config.getAccessToken,
  });

  // Initialize all services
  const auth = createAuthService(apiClient);
  const users = createUserService(apiClient);
  const roles = createRoleService(apiClient);
  const permissions = createPermissionService(apiClient);
  const resources = createResourceService(apiClient);
  const organizations = createOrganizationService(apiClient);
  const actions = createActionService(apiClient);
  const contacts = createContactService(apiClient);
  const modules = createModuleService(apiClient);

  return {
    auth,
    users,
    roles,
    permissions,
    resources,
    organizations,
    actions,
    contacts,
    modules,
  };
};

export default createAAAService;

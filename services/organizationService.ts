import { ApiClient } from '../utils/apiClient';
import { authServiceConfig } from '../config';

export interface OrganizationListParams {
  limit?: number;
  offset?: number;
  type?: string;
  include_inactive?: boolean;
  search?: string;
}

export interface CreateOrganizationRequest {
  name: string;
  type: string;
  description?: string;
  parent_id?: string;
  metadata?: Record<string, unknown>;
}

export interface UpdateOrganizationRequest {
  name?: string;
  type?: string;
  description?: string;
  parent_id?: string;
  metadata?: Record<string, unknown>;
}

export class OrganizationServiceClient {
  private readonly api: ApiClient;

  constructor(api: ApiClient = new ApiClient({
    baseURL: authServiceConfig.baseURL,
    defaultHeaders: authServiceConfig.defaultHeaders,
    getAccessToken: authServiceConfig.getAccessToken
  })) {
    this.api = api;
  }

  // List organizations
  list(params?: OrganizationListParams) {
    return this.api.get('/api/v1/organizations', { params });
  }

  // Create organization
  create(payload: CreateOrganizationRequest) {
    return this.api.post('/api/v1/organizations', payload);
  }

  // Get organization by ID
  getById(orgId: string) {
    return this.api.get(`/api/v1/organizations/${orgId}`);
  }

  // Update organization
  update(orgId: string, payload: UpdateOrganizationRequest) {
    return this.api.put(`/api/v1/organizations/${orgId}`, payload);
  }

  // Delete organization
  delete(orgId: string) {
    return this.api.delete(`/api/v1/organizations/${orgId}`);
  }

  // Activate organization
  activate(orgId: string) {
    return this.api.post(`/api/v1/organizations/${orgId}/activate`, {});
  }

  // Deactivate organization
  deactivate(orgId: string) {
    return this.api.post(`/api/v1/organizations/${orgId}/deactivate`, {});
  }

  // Get organization hierarchy
  getHierarchy(orgId: string) {
    return this.api.get(`/api/v1/organizations/${orgId}/hierarchy`);
  }

  // Get organization stats
  getStats(orgId: string) {
    return this.api.get(`/api/v1/organizations/${orgId}/stats`);
  }

  // Group management
  // List groups in organization
  listGroups(orgId: string, params?: { limit?: number; offset?: number }) {
    return this.api.get(`/api/v1/organizations/${orgId}/groups`, { params });
  }

  // Create group in organization
  createGroup(orgId: string, payload: { name: string; description?: string }) {
    return this.api.post(`/api/v1/organizations/${orgId}/groups`, payload);
  }

  // Get group by ID
  getGroup(orgId: string, groupId: string) {
    return this.api.get(`/api/v1/organizations/${orgId}/groups/${groupId}`);
  }

  // Update group
  updateGroup(orgId: string, groupId: string, payload: { name?: string; description?: string }) {
    return this.api.put(`/api/v1/organizations/${orgId}/groups/${groupId}`, payload);
  }

  // Delete group
  deleteGroup(orgId: string, groupId: string) {
    return this.api.delete(`/api/v1/organizations/${orgId}/groups/${groupId}`);
  }

  // Group roles
  // Get group roles
  getGroupRoles(orgId: string, groupId: string) {
    return this.api.get(`/api/v1/organizations/${orgId}/groups/${groupId}/roles`);
  }

  // Assign role to group
  assignRoleToGroup(orgId: string, groupId: string, roleId: string) {
    return this.api.post(`/api/v1/organizations/${orgId}/groups/${groupId}/roles/${roleId}`, {});
  }

  // Remove role from group
  removeRoleFromGroup(orgId: string, groupId: string, roleId: string) {
    return this.api.delete(`/api/v1/organizations/${orgId}/groups/${groupId}/roles/${roleId}`);
  }

  // Group users
  // Get group users
  getGroupUsers(orgId: string, groupId: string, params?: { limit?: number; offset?: number }) {
    return this.api.get(`/api/v1/organizations/${orgId}/groups/${groupId}/users`, { params });
  }

  // Add user to group
  addUserToGroup(orgId: string, groupId: string, userId: string) {
    return this.api.post(`/api/v1/organizations/${orgId}/groups/${groupId}/users/${userId}`, {});
  }

  // Remove user from group
  removeUserFromGroup(orgId: string, groupId: string, userId: string) {
    return this.api.delete(`/api/v1/organizations/${orgId}/groups/${groupId}/users/${userId}`);
  }

  // User effective roles in organization
  getUserEffectiveRoles(orgId: string, userId: string) {
    return this.api.get(`/api/v1/organizations/${orgId}/users/${userId}/effective-roles`);
  }

  // Get user groups in organization
  getUserGroups(orgId: string, userId: string) {
    return this.api.get(`/api/v1/organizations/${orgId}/users/${userId}/groups`);
  }
}

export const organizationServiceClient = new OrganizationServiceClient();


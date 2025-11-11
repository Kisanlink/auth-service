/**
 * Mock Server for Integration Tests
 *
 * This mock server simulates API responses with realistic data and edge cases.
 * It includes validation logic, state management, and error simulation capabilities.
 */

import { vi } from 'vitest';

export interface MockServerConfig {
  baseURL: string;
  failureRate?: number; // Simulate random failures
  latency?: number; // Simulate network latency
}

interface MockUser {
  id: string;
  name?: string;
  email?: string;
  phone_number: string;
  country_code: string;
  password_hash: string; // In real scenario this would be hashed
  mpin?: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  roles: Array<{ id: string; role: { id: string; name: string } }>;
  organization_id?: string;
  group_ids?: string[];
}

interface MockRole {
  id: string;
  name: string;
  description?: string;
  is_active: boolean;
  permission_ids: string[];
  resource_ids: string[];
  created_at: string;
  updated_at: string;
}

interface MockPermission {
  id: string;
  name: string;
  description?: string;
  action_id?: string;
  resource_id?: string;
  created_at: string;
  updated_at: string;
}

interface MockOrganization {
  id: string;
  name: string;
  type: string;
  description?: string;
  parent_id?: string;
  is_active: boolean;
  metadata?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

interface MockGroup {
  id: string;
  organization_id: string;
  name: string;
  description?: string;
  role_ids: string[];
  user_ids: string[];
  created_at: string;
  updated_at: string;
}

interface MockSession {
  access_token: string;
  refresh_token: string;
  user_id: string;
  expires_at: number;
  created_at: number;
}

export class MockServer {
  private users: Map<string, MockUser> = new Map();
  private roles: Map<string, MockRole> = new Map();
  private permissions: Map<string, MockPermission> = new Map();
  private organizations: Map<string, MockOrganization> = new Map();
  private groups: Map<string, MockGroup> = new Map();
  private sessions: Map<string, MockSession> = new Map();
  private refreshTokens: Map<string, MockSession> = new Map();

  // Track request history for validation
  private requestHistory: Array<{ method: string; url: string; body?: any; timestamp: number }> = [];

  // Simulate concurrent operation locks
  private locks: Map<string, number> = new Map();

  // Track failed login attempts for security testing
  private failedAttempts: Map<string, number> = new Map();

  constructor(private config: MockServerConfig) {
    this.seedInitialData();
  }

  private seedInitialData() {
    // Create default test users
    const testUser1: MockUser = {
      id: 'user-001',
      name: 'Test User 1',
      email: 'test1@example.com',
      phone_number: '1234567890',
      country_code: '+1',
      password_hash: 'password123', // Plain for testing
      mpin: '1234',
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      roles: [],
      organization_id: 'org-001',
      group_ids: ['group-001']
    };

    const testUser2: MockUser = {
      id: 'user-002',
      name: 'Test User 2',
      phone_number: '9876543210',
      country_code: '+91',
      password_hash: 'password456',
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      roles: [],
    };

    // Inactive user for testing
    const inactiveUser: MockUser = {
      id: 'user-inactive',
      name: 'Inactive User',
      phone_number: '5555555555',
      country_code: '+1',
      password_hash: 'password789',
      is_active: false,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      roles: [],
    };

    this.users.set(testUser1.id, testUser1);
    this.users.set(testUser2.id, testUser2);
    this.users.set(inactiveUser.id, inactiveUser);

    // Create default roles
    const adminRole: MockRole = {
      id: 'role-admin',
      name: 'Admin',
      description: 'Administrator role',
      is_active: true,
      permission_ids: ['perm-001', 'perm-002', 'perm-003'],
      resource_ids: ['res-001', 'res-002'],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const userRole: MockRole = {
      id: 'role-user',
      name: 'User',
      description: 'Regular user role',
      is_active: true,
      permission_ids: ['perm-001'],
      resource_ids: ['res-001'],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    this.roles.set(adminRole.id, adminRole);
    this.roles.set(userRole.id, userRole);

    // Create permissions
    const viewPerm: MockPermission = {
      id: 'perm-001',
      name: 'dashboard:view',
      description: 'View dashboard',
      action_id: 'action-view',
      resource_id: 'res-dashboard',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const editPerm: MockPermission = {
      id: 'perm-002',
      name: 'users:edit',
      description: 'Edit users',
      action_id: 'action-edit',
      resource_id: 'res-users',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const deletePerm: MockPermission = {
      id: 'perm-003',
      name: 'users:delete',
      description: 'Delete users',
      action_id: 'action-delete',
      resource_id: 'res-users',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    this.permissions.set(viewPerm.id, viewPerm);
    this.permissions.set(editPerm.id, editPerm);
    this.permissions.set(deletePerm.id, deletePerm);

    // Create organizations
    const org1: MockOrganization = {
      id: 'org-001',
      name: 'Test Organization',
      type: 'company',
      description: 'Main test organization',
      is_active: true,
      metadata: { tier: 'premium' },
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const org2: MockOrganization = {
      id: 'org-002',
      name: 'Child Organization',
      type: 'subsidiary',
      parent_id: 'org-001',
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    this.organizations.set(org1.id, org1);
    this.organizations.set(org2.id, org2);

    // Create groups
    const group1: MockGroup = {
      id: 'group-001',
      organization_id: 'org-001',
      name: 'Administrators',
      description: 'Admin group',
      role_ids: ['role-admin'],
      user_ids: ['user-001'],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    this.groups.set(group1.id, group1);
  }

  // Helper to simulate latency
  private async simulateLatency() {
    if (this.config.latency) {
      await new Promise(resolve => setTimeout(resolve, this.config.latency));
    }
  }

  // Helper to simulate failures
  private shouldFail(): boolean {
    if (this.config.failureRate) {
      return Math.random() < this.config.failureRate;
    }
    return false;
  }

  // Generate tokens
  private generateTokens(userId: string): { access_token: string; refresh_token: string } {
    const access_token = `access_${userId}_${Date.now()}_${Math.random().toString(36)}`;
    const refresh_token = `refresh_${userId}_${Date.now()}_${Math.random().toString(36)}`;

    const session: MockSession = {
      access_token,
      refresh_token,
      user_id: userId,
      expires_at: Date.now() + 3600000, // 1 hour
      created_at: Date.now(),
    };

    this.sessions.set(access_token, session);
    this.refreshTokens.set(refresh_token, session);

    return { access_token, refresh_token };
  }

  // Validate token
  private validateToken(authHeader?: string): MockSession | null {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }
    const token = authHeader.replace('Bearer ', '');
    const session = this.sessions.get(token);

    if (!session || session.expires_at < Date.now()) {
      return null;
    }

    return session;
  }

  // Check for concurrent operations (race condition simulation)
  private checkConcurrentOperation(key: string): boolean {
    const lastOperation = this.locks.get(key);
    const now = Date.now();

    if (lastOperation && now - lastOperation < 100) {
      // Operation attempted within 100ms - potential race condition
      return true;
    }

    this.locks.set(key, now);
    return false;
  }

  // API Handlers
  async handleRequest(method: string, url: string, body?: any, headers?: Record<string, string>): Promise<any> {
    await this.simulateLatency();

    // Track request
    this.requestHistory.push({ method, url, body, timestamp: Date.now() });

    // Random failure simulation
    if (this.shouldFail()) {
      throw new Error('Random server failure (503 Service Unavailable)');
    }

    // Route requests
    const urlPath = url.replace(this.config.baseURL, '');

    // Auth endpoints
    if (urlPath === '/api/v1/auth/login' && method === 'POST') {
      return this.handleLogin(body);
    }

    if (urlPath === '/api/v1/auth/register' && method === 'POST') {
      return this.handleRegister(body);
    }

    if (urlPath === '/api/v1/auth/logout' && method === 'POST') {
      return this.handleLogout(headers?.['Authorization']);
    }

    if (urlPath === '/api/v1/auth/refresh' && method === 'POST') {
      return this.handleRefresh(body);
    }

    if (urlPath === '/api/v1/auth/set-mpin' && method === 'POST') {
      return this.handleSetMPin(body, headers?.['Authorization']);
    }

    if (urlPath === '/api/v1/auth/update-mpin' && method === 'POST') {
      return this.handleUpdateMPin(body, headers?.['Authorization']);
    }

    // User endpoints
    if (urlPath === '/api/v1/users' && method === 'GET') {
      return this.handleListUsers(headers?.['Authorization']);
    }

    if (urlPath === '/api/v1/users' && method === 'POST') {
      return this.handleCreateUser(body, headers?.['Authorization']);
    }

    if (urlPath.match(/^\/api\/v1\/users\/[^\/]+$/) && method === 'GET') {
      const userId = urlPath.split('/').pop()!;
      return this.handleGetUser(userId, headers?.['Authorization']);
    }

    if (urlPath.match(/^\/api\/v1\/users\/[^\/]+$/) && method === 'PUT') {
      const userId = urlPath.split('/').pop()!;
      return this.handleUpdateUser(userId, body, headers?.['Authorization']);
    }

    if (urlPath.match(/^\/api\/v1\/users\/[^\/]+$/) && method === 'DELETE') {
      const userId = urlPath.split('/').pop()!;
      return this.handleDeleteUser(userId, headers?.['Authorization']);
    }

    // Permission evaluation
    if (urlPath === '/api/v1/permissions/evaluate' && method === 'POST') {
      return this.handleEvaluatePermission(body, headers?.['Authorization']);
    }

    // Add more endpoint handlers as needed...

    throw new Error(`Unhandled request: ${method} ${urlPath}`);
  }

  // Auth Handlers
  private handleLogin(body: any) {
    const { country_code, phone_number, password } = body;

    // Validation
    if (!phone_number || !password) {
      throw new Error('Phone number and password are required');
    }

    // Check for too many failed attempts (brute force protection)
    const attemptKey = `${country_code}:${phone_number}`;
    const attempts = this.failedAttempts.get(attemptKey) || 0;
    if (attempts >= 5) {
      throw new Error('Account locked due to too many failed attempts');
    }

    // Find user
    const user = Array.from(this.users.values()).find(
      u => u.phone_number === phone_number && u.country_code === (country_code || '+1')
    );

    if (!user) {
      this.failedAttempts.set(attemptKey, attempts + 1);
      throw new Error('Invalid credentials');
    }

    if (!user.is_active) {
      throw new Error('Account is disabled');
    }

    if (user.password_hash !== password) {
      this.failedAttempts.set(attemptKey, attempts + 1);
      throw new Error('Invalid credentials');
    }

    // Clear failed attempts on successful login
    this.failedAttempts.delete(attemptKey);

    // Generate tokens
    const tokens = this.generateTokens(user.id);

    // Get user permissions
    const permissions = this.getUserPermissions(user.id);

    return {
      ...tokens,
      user: {
        id: user.id,
        name: user.name,
        phone_number: user.phone_number,
        roles: user.roles,
      },
      permissions,
    };
  }

  private handleRegister(body: any) {
    const { country_code, phone_number, password, name } = body;

    // Validation
    if (!phone_number || !password) {
      throw new Error('Phone number and password are required');
    }

    // Password strength validation
    if (password.length < 8) {
      throw new Error('Password must be at least 8 characters');
    }

    // Phone number format validation
    if (!/^\d{10}$/.test(phone_number)) {
      throw new Error('Invalid phone number format');
    }

    // Check for race condition on duplicate phone numbers
    const concurrencyKey = `register:${country_code}:${phone_number}`;
    if (this.checkConcurrentOperation(concurrencyKey)) {
      throw new Error('Concurrent registration attempt detected');
    }

    // Check if user exists
    const existingUser = Array.from(this.users.values()).find(
      u => u.phone_number === phone_number && u.country_code === (country_code || '+1')
    );

    if (existingUser) {
      throw new Error('User with this phone number already exists');
    }

    // Create new user
    const newUser: MockUser = {
      id: `user-${Date.now()}-${Math.random().toString(36)}`,
      name,
      phone_number,
      country_code: country_code || '+1',
      password_hash: password,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      roles: [],
    };

    this.users.set(newUser.id, newUser);

    // Auto-login after registration
    const tokens = this.generateTokens(newUser.id);

    return {
      ...tokens,
      user: {
        id: newUser.id,
        name: newUser.name,
        phone_number: newUser.phone_number,
        roles: newUser.roles,
      },
      permissions: [],
    };
  }

  private handleLogout(authHeader?: string) {
    const session = this.validateToken(authHeader);
    if (!session) {
      throw new Error('Unauthorized');
    }

    // Invalidate tokens
    this.sessions.delete(session.access_token);
    this.refreshTokens.delete(session.refresh_token);

    return {};
  }

  private handleRefresh(body: any) {
    const { mpin, refresh_token } = body;

    if (!refresh_token || !mpin) {
      throw new Error('Refresh token and MPIN are required');
    }

    const session = this.refreshTokens.get(refresh_token);
    if (!session) {
      throw new Error('Invalid refresh token');
    }

    const user = this.users.get(session.user_id);
    if (!user) {
      throw new Error('User not found');
    }

    // Validate MPIN
    if (user.mpin !== mpin) {
      throw new Error('Invalid MPIN');
    }

    // Invalidate old tokens
    this.sessions.delete(session.access_token);
    this.refreshTokens.delete(session.refresh_token);

    // Generate new tokens
    const tokens = this.generateTokens(user.id);

    return tokens;
  }

  private handleSetMPin(body: any, authHeader?: string) {
    const session = this.validateToken(authHeader);
    if (!session) {
      throw new Error('Unauthorized');
    }

    const { mpin } = body;

    if (!mpin || !/^\d{4,6}$/.test(mpin)) {
      throw new Error('MPIN must be 4-6 digits');
    }

    const user = this.users.get(session.user_id);
    if (!user) {
      throw new Error('User not found');
    }

    if (user.mpin) {
      throw new Error('MPIN already set');
    }

    user.mpin = mpin;
    user.updated_at = new Date().toISOString();

    return {};
  }

  private handleUpdateMPin(body: any, authHeader?: string) {
    const session = this.validateToken(authHeader);
    if (!session) {
      throw new Error('Unauthorized');
    }

    const { old_mpin, new_mpin } = body;

    if (!new_mpin || !/^\d{4,6}$/.test(new_mpin)) {
      throw new Error('New MPIN must be 4-6 digits');
    }

    const user = this.users.get(session.user_id);
    if (!user) {
      throw new Error('User not found');
    }

    if (!user.mpin) {
      throw new Error('MPIN not set');
    }

    if (old_mpin && user.mpin !== old_mpin) {
      throw new Error('Invalid old MPIN');
    }

    if (new_mpin === user.mpin) {
      throw new Error('New MPIN must be different from old MPIN');
    }

    user.mpin = new_mpin;
    user.updated_at = new Date().toISOString();

    return {};
  }

  // User Handlers
  private handleListUsers(authHeader?: string) {
    const session = this.validateToken(authHeader);
    if (!session) {
      throw new Error('Unauthorized');
    }

    const users = Array.from(this.users.values()).map(u => ({
      id: u.id,
      name: u.name,
      email: u.email,
      phone_number: u.phone_number,
      country_code: u.country_code,
      is_active: u.is_active,
      roles: u.roles,
      created_at: u.created_at,
      updated_at: u.updated_at,
    }));

    return { data: users, total: users.length };
  }

  private handleCreateUser(body: any, authHeader?: string) {
    const session = this.validateToken(authHeader);
    if (!session) {
      throw new Error('Unauthorized');
    }

    // Check admin permission
    if (!this.userHasPermission(session.user_id, 'users:create')) {
      throw new Error('Insufficient permissions');
    }

    const { country_code, phone_number, password, name, email, username, role_ids } = body;

    // Validation
    if (!phone_number || !password) {
      throw new Error('Phone number and password are required');
    }

    // Check for duplicate phone
    const concurrencyKey = `create-user:${country_code}:${phone_number}`;
    if (this.checkConcurrentOperation(concurrencyKey)) {
      throw new Error('Concurrent user creation detected');
    }

    const existingUser = Array.from(this.users.values()).find(
      u => u.phone_number === phone_number && u.country_code === (country_code || '+1')
    );

    if (existingUser) {
      throw new Error('User with this phone number already exists');
    }

    // Check for duplicate email
    if (email) {
      const emailUser = Array.from(this.users.values()).find(u => u.email === email);
      if (emailUser) {
        throw new Error('User with this email already exists');
      }
    }

    // Create user
    const newUser: MockUser = {
      id: `user-${Date.now()}-${Math.random().toString(36)}`,
      name,
      email,
      phone_number,
      country_code: country_code || '+1',
      password_hash: password,
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      roles: [],
    };

    // Assign roles
    if (role_ids && Array.isArray(role_ids)) {
      for (const roleId of role_ids) {
        if (!this.roles.has(roleId)) {
          throw new Error(`Role ${roleId} not found`);
        }
        newUser.roles.push({
          id: `user-role-${Date.now()}`,
          role: { id: roleId, name: this.roles.get(roleId)!.name },
        });
      }
    }

    this.users.set(newUser.id, newUser);

    return {
      id: newUser.id,
      name: newUser.name,
      email: newUser.email,
      phone_number: newUser.phone_number,
      country_code: newUser.country_code,
      is_active: newUser.is_active,
      roles: newUser.roles,
      created_at: newUser.created_at,
      updated_at: newUser.updated_at,
    };
  }

  private handleGetUser(userId: string, authHeader?: string) {
    const session = this.validateToken(authHeader);
    if (!session) {
      throw new Error('Unauthorized');
    }

    const user = this.users.get(userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Check if user can view this user
    if (session.user_id !== userId && !this.userHasPermission(session.user_id, 'users:view')) {
      throw new Error('Insufficient permissions');
    }

    return {
      id: user.id,
      name: user.name,
      email: user.email,
      phone_number: user.phone_number,
      country_code: user.country_code,
      is_active: user.is_active,
      roles: user.roles,
      organization_id: user.organization_id,
      group_ids: user.group_ids,
      created_at: user.created_at,
      updated_at: user.updated_at,
    };
  }

  private handleUpdateUser(userId: string, body: any, authHeader?: string) {
    const session = this.validateToken(authHeader);
    if (!session) {
      throw new Error('Unauthorized');
    }

    const user = this.users.get(userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Check permission
    if (session.user_id !== userId && !this.userHasPermission(session.user_id, 'users:edit')) {
      throw new Error('Insufficient permissions');
    }

    // Update fields
    if (body.name !== undefined) user.name = body.name;
    if (body.email !== undefined) {
      // Check duplicate email
      const emailUser = Array.from(this.users.values()).find(
        u => u.id !== userId && u.email === body.email
      );
      if (emailUser) {
        throw new Error('Email already in use');
      }
      user.email = body.email;
    }
    if (body.phone_number !== undefined) {
      // Check duplicate phone
      const phoneUser = Array.from(this.users.values()).find(
        u => u.id !== userId && u.phone_number === body.phone_number && u.country_code === (body.country_code || user.country_code)
      );
      if (phoneUser) {
        throw new Error('Phone number already in use');
      }
      user.phone_number = body.phone_number;
    }
    if (body.country_code !== undefined) user.country_code = body.country_code;

    user.updated_at = new Date().toISOString();

    return {
      id: user.id,
      name: user.name,
      email: user.email,
      phone_number: user.phone_number,
      country_code: user.country_code,
      is_active: user.is_active,
      roles: user.roles,
      created_at: user.created_at,
      updated_at: user.updated_at,
    };
  }

  private handleDeleteUser(userId: string, authHeader?: string) {
    const session = this.validateToken(authHeader);
    if (!session) {
      throw new Error('Unauthorized');
    }

    // Check permission
    if (!this.userHasPermission(session.user_id, 'users:delete')) {
      throw new Error('Insufficient permissions');
    }

    const user = this.users.get(userId);
    if (!user) {
      throw new Error('User not found');
    }

    // Can't delete yourself
    if (session.user_id === userId) {
      throw new Error('Cannot delete your own account');
    }

    // Remove from groups
    this.groups.forEach(group => {
      const idx = group.user_ids.indexOf(userId);
      if (idx > -1) {
        group.user_ids.splice(idx, 1);
      }
    });

    this.users.delete(userId);

    return {};
  }

  // Permission Handlers
  private handleEvaluatePermission(body: any, authHeader?: string) {
    const session = this.validateToken(authHeader);
    if (!session) {
      throw new Error('Unauthorized');
    }

    const { user_id, permission, context } = body;

    if (!user_id || !permission) {
      throw new Error('User ID and permission are required');
    }

    const allowed = this.userHasPermission(user_id, permission, context);

    return {
      allowed,
      reasons: allowed ? ['Permission granted'] : ['Permission denied'],
    };
  }

  // Helper methods
  private getUserPermissions(userId: string): string[] {
    const user = this.users.get(userId);
    if (!user) return [];

    const permissions = new Set<string>();

    // Direct role permissions
    user.roles.forEach(userRole => {
      const role = this.roles.get(userRole.role.id);
      if (role && role.is_active) {
        role.permission_ids.forEach(permId => {
          const perm = this.permissions.get(permId);
          if (perm) permissions.add(perm.name);
        });
      }
    });

    // Group role permissions
    if (user.group_ids) {
      user.group_ids.forEach(groupId => {
        const group = this.groups.get(groupId);
        if (group) {
          group.role_ids.forEach(roleId => {
            const role = this.roles.get(roleId);
            if (role && role.is_active) {
              role.permission_ids.forEach(permId => {
                const perm = this.permissions.get(permId);
                if (perm) permissions.add(perm.name);
              });
            }
          });
        }
      });
    }

    return Array.from(permissions);
  }

  private userHasPermission(userId: string, permission: string, context?: any): boolean {
    const permissions = this.getUserPermissions(userId);

    // Direct permission check
    if (permissions.includes(permission)) {
      return true;
    }

    // Wildcard permission check (e.g., 'users:*' grants 'users:edit')
    const [resource, action] = permission.split(':');
    if (permissions.includes(`${resource}:*`)) {
      return true;
    }

    // Super admin check
    if (permissions.includes('*:*')) {
      return true;
    }

    // Context-based permission check
    if (context) {
      // Example: Check if user owns the resource
      if (context.owner_id === userId && permissions.includes(`${resource}:own`)) {
        return true;
      }
    }

    return false;
  }

  // Public methods for testing
  reset() {
    this.users.clear();
    this.roles.clear();
    this.permissions.clear();
    this.organizations.clear();
    this.groups.clear();
    this.sessions.clear();
    this.refreshTokens.clear();
    this.requestHistory = [];
    this.locks.clear();
    this.failedAttempts.clear();
    this.seedInitialData();
  }

  getRequestHistory() {
    return this.requestHistory;
  }

  getUserByPhone(country_code: string, phone_number: string): MockUser | undefined {
    return Array.from(this.users.values()).find(
      u => u.phone_number === phone_number && u.country_code === country_code
    );
  }

  getSessionByToken(token: string): MockSession | undefined {
    return this.sessions.get(token);
  }
}

// Create a singleton mock server instance
let mockServerInstance: MockServer | null = null;

export function createMockServer(config?: Partial<MockServerConfig>): MockServer {
  const defaultConfig: MockServerConfig = {
    baseURL: 'http://mock-api.test',
    failureRate: 0,
    latency: 0,
    ...config,
  };

  mockServerInstance = new MockServer(defaultConfig);
  return mockServerInstance;
}

export function getMockServer(): MockServer {
  if (!mockServerInstance) {
    throw new Error('Mock server not initialized. Call createMockServer() first.');
  }
  return mockServerInstance;
}

// Mock fetch implementation
export function setupMockFetch() {
  global.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const mockServer = getMockServer();
    const urlString = typeof url === 'string' ? url : url.toString();
    const method = init?.method || 'GET';
    const body = init?.body ? JSON.parse(init.body as string) : undefined;
    const headers = init?.headers as Record<string, string>;

    try {
      const response = await mockServer.handleRequest(method, urlString, body, headers);

      return {
        ok: true,
        status: 200,
        json: async () => response,
        text: async () => JSON.stringify(response),
      } as Response;
    } catch (error: any) {
      const status = error.message.includes('Unauthorized') ? 401 :
                     error.message.includes('Insufficient permissions') ? 403 :
                     error.message.includes('not found') ? 404 :
                     error.message.includes('already exists') ? 409 :
                     error.message.includes('Invalid') ? 400 :
                     error.message.includes('Random server failure') ? 503 : 500;

      return {
        ok: false,
        status,
        json: async () => ({ error: error.message }),
        text: async () => JSON.stringify({ error: error.message }),
      } as Response;
    }
  }) as any;
}

export function clearMockFetch() {
  if (global.fetch && 'mockClear' in global.fetch) {
    (global.fetch as any).mockClear();
  }
}
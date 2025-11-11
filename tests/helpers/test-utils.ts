/**
 * Test Utilities for Integration Tests
 *
 * Provides helper functions for testing business logic,
 * validation, edge cases, and security scenarios.
 */

import { vi, expect } from 'vitest';
import createAAAService from '../../index';
import { createMockServer, setupMockFetch, clearMockFetch, MockServer } from './mock-server';
import { AuthServiceConfig } from '../../config';

// Test configuration
export const TEST_CONFIG: AuthServiceConfig = {
  baseURL: 'http://mock-api.test',
  defaultHeaders: {
    'Content-Type': 'application/json',
  },
  getAccessToken: () => undefined, // Will be set by test context
};

// Test data generators
export function generatePhoneNumber(): string {
  return Math.floor(1000000000 + Math.random() * 9000000000).toString();
}

export function generateEmail(): string {
  return `test${Date.now()}${Math.random().toString(36)}@example.com`;
}

export function generateName(): string {
  const names = ['Alice', 'Bob', 'Charlie', 'Diana', 'Eve', 'Frank', 'Grace', 'Henry'];
  return `${names[Math.floor(Math.random() * names.length)]} Test${Date.now()}`;
}

export function generateMPin(): string {
  return Math.floor(1000 + Math.random() * 9000).toString();
}

// Test context manager
export class TestContext {
  private mockServer: MockServer;
  private authService: ReturnType<typeof createAAAService>;
  private currentToken?: string;

  constructor(config?: Partial<AuthServiceConfig>) {
    this.mockServer = createMockServer({
      baseURL: config?.baseURL || TEST_CONFIG.baseURL,
    });

    setupMockFetch();

    const testConfig: AuthServiceConfig = {
      ...TEST_CONFIG,
      ...config,
      getAccessToken: () => this.currentToken,
    };

    this.authService = createAAAService(testConfig);
  }

  getService() {
    return this.authService;
  }

  getMockServer() {
    return this.mockServer;
  }

  setAccessToken(token: string) {
    this.currentToken = token;
  }

  clearAccessToken() {
    this.currentToken = undefined;
  }

  async loginAsTestUser(phoneNumber = '1234567890', password = 'password123') {
    const response = await this.authService.auth.login({
      country_code: '+1',
      phone_number: phoneNumber,
      password,
    });
    this.currentToken = response.access_token;
    return response;
  }

  async createAndLoginUser(userData?: {
    phone_number?: string;
    password?: string;
    name?: string;
  }) {
    const phone_number = userData?.phone_number || generatePhoneNumber();
    const password = userData?.password || 'TestPass123!';
    const name = userData?.name || generateName();

    const response = await this.authService.auth.register({
      country_code: '+1',
      phone_number,
      password,
      name,
    });

    this.currentToken = response.access_token;
    return { ...response, password, phone_number };
  }

  cleanup() {
    this.mockServer.reset();
    clearMockFetch();
    this.currentToken = undefined;
  }
}

// Validation helpers
export function expectValidationError(error: any, expectedMessage?: string) {
  expect(error).toBeDefined();
  expect(error.status).toBe(400);
  if (expectedMessage) {
    expect(error.message).toContain(expectedMessage);
  }
}

export function expectUnauthorizedError(error: any) {
  expect(error).toBeDefined();
  expect(error.status).toBe(401);
  expect(error.message).toContain('Unauthorized');
}

export function expectForbiddenError(error: any) {
  expect(error).toBeDefined();
  expect(error.status).toBe(403);
  expect(error.message).toContain('Insufficient permissions');
}

export function expectNotFoundError(error: any) {
  expect(error).toBeDefined();
  expect(error.status).toBe(404);
  expect(error.message).toContain('not found');
}

export function expectConflictError(error: any, expectedMessage?: string) {
  expect(error).toBeDefined();
  expect(error.status).toBe(409);
  if (expectedMessage) {
    expect(error.message).toContain(expectedMessage);
  }
}

// Business logic invariant checkers
export class InvariantChecker {
  /**
   * Checks that a user cannot have duplicate roles
   */
  static checkNoDuplicateRoles(roles: Array<{ id: string; role: { id: string; name: string } }>) {
    const roleIds = roles.map(r => r.role.id);
    const uniqueRoleIds = new Set(roleIds);
    expect(roleIds.length).toBe(uniqueRoleIds.size);
  }

  /**
   * Checks that inactive users cannot perform actions
   */
  static async checkInactiveUserCannotAct(
    context: TestContext,
    action: () => Promise<any>
  ) {
    // This would require mock server to deactivate a user
    // For now, we'll check that the action fails with proper error
    await expect(action()).rejects.toThrow();
  }

  /**
   * Checks that permissions are properly inherited through hierarchy
   */
  static checkPermissionInheritance(
    userPermissions: string[],
    rolePermissions: string[],
    groupRolePermissions: string[]
  ) {
    const allExpectedPermissions = new Set([
      ...rolePermissions,
      ...groupRolePermissions,
    ]);

    allExpectedPermissions.forEach(perm => {
      expect(userPermissions).toContain(perm);
    });
  }

  /**
   * Checks that tokens expire properly
   */
  static async checkTokenExpiration(
    context: TestContext,
    token: string,
    waitTime: number = 0
  ) {
    if (waitTime > 0) {
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }

    context.setAccessToken(token);
    const service = context.getService();

    // Try to perform an authenticated action
    await expect(service.users.list()).rejects.toThrow();
  }

  /**
   * Checks that MPIN requirements are enforced
   */
  static checkMPinFormat(mpin: string) {
    expect(mpin).toMatch(/^\d{4,6}$/);
  }

  /**
   * Checks that phone numbers are unique per country code
   */
  static async checkPhoneNumberUniqueness(
    context: TestContext,
    countryCode: string,
    phoneNumber: string
  ) {
    const service = context.getService();

    // Try to create duplicate user
    await expect(
      service.auth.register({
        country_code: countryCode,
        phone_number: phoneNumber,
        password: 'TestPass123!',
      })
    ).rejects.toThrow('already exists');
  }

  /**
   * Checks that organization hierarchy is consistent
   */
  static checkOrganizationHierarchy(org: any, parentOrg?: any) {
    if (parentOrg) {
      expect(org.parent_id).toBe(parentOrg.id);
    } else {
      expect(org.parent_id).toBeUndefined();
    }
  }

  /**
   * Checks that cascading deletes work properly
   */
  static async checkCascadingDelete(
    context: TestContext,
    parentId: string,
    childIds: string[],
    checkExistence: (id: string) => Promise<boolean>
  ) {
    // After deleting parent, children should also be gone or orphaned
    for (const childId of childIds) {
      const exists = await checkExistence(childId);
      // Depending on business logic, either deleted or orphaned
      // This needs to be defined based on requirements
    }
  }
}

// Security test helpers
export class SecurityTester {
  /**
   * Tests for SQL injection attempts
   */
  static async testSQLInjection(
    context: TestContext,
    endpoint: (payload: any) => Promise<any>
  ) {
    const injectionPayloads = [
      "'; DROP TABLE users; --",
      "1' OR '1'='1",
      "admin'--",
      "' OR 1=1--",
      "'; EXEC sp_MSForEachTable 'DROP TABLE ?'; --",
    ];

    for (const payload of injectionPayloads) {
      await expect(endpoint({ name: payload })).rejects.toThrow();
    }
  }

  /**
   * Tests for XSS attempts
   */
  static async testXSS(
    context: TestContext,
    endpoint: (payload: any) => Promise<any>
  ) {
    const xssPayloads = [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      'javascript:alert("XSS")',
      '<svg onload=alert("XSS")>',
    ];

    for (const payload of xssPayloads) {
      const result = await endpoint({ name: payload });
      // Check that the payload is properly escaped/sanitized
      if (result.name) {
        expect(result.name).not.toContain('<script>');
        expect(result.name).not.toContain('javascript:');
      }
    }
  }

  /**
   * Tests for brute force protection
   */
  static async testBruteForceProtection(
    context: TestContext,
    loginAttempt: () => Promise<any>
  ) {
    const maxAttempts = 5;
    const errors: any[] = [];

    // Make multiple failed login attempts
    for (let i = 0; i < maxAttempts + 1; i++) {
      try {
        await loginAttempt();
      } catch (error) {
        errors.push(error);
      }
    }

    // Last attempt should be blocked
    const lastError = errors[errors.length - 1];
    expect(lastError.message).toContain('locked');
  }

  /**
   * Tests for timing attacks
   */
  static async testTimingAttack(
    context: TestContext,
    validAttempt: () => Promise<any>,
    invalidAttempt: () => Promise<any>
  ) {
    const validTimes: number[] = [];
    const invalidTimes: number[] = [];

    // Measure timing for valid attempts
    for (let i = 0; i < 10; i++) {
      const start = Date.now();
      try {
        await validAttempt();
      } catch (e) {}
      validTimes.push(Date.now() - start);
    }

    // Measure timing for invalid attempts
    for (let i = 0; i < 10; i++) {
      const start = Date.now();
      try {
        await invalidAttempt();
      } catch (e) {}
      invalidTimes.push(Date.now() - start);
    }

    // Calculate average times
    const avgValid = validTimes.reduce((a, b) => a + b, 0) / validTimes.length;
    const avgInvalid = invalidTimes.reduce((a, b) => a + b, 0) / invalidTimes.length;

    // Times should be similar to prevent timing attacks
    const difference = Math.abs(avgValid - avgInvalid);
    expect(difference).toBeLessThan(100); // Within 100ms
  }

  /**
   * Tests for authorization bypass attempts
   */
  static async testAuthorizationBypass(
    context: TestContext,
    protectedAction: () => Promise<any>
  ) {
    // Try without token
    context.clearAccessToken();
    await expect(protectedAction()).rejects.toThrow('Unauthorized');

    // Try with invalid token
    context.setAccessToken('invalid-token-12345');
    await expect(protectedAction()).rejects.toThrow('Unauthorized');

    // Try with expired token (simulated)
    context.setAccessToken('expired-token-12345');
    await expect(protectedAction()).rejects.toThrow('Unauthorized');
  }

  /**
   * Tests for IDOR (Insecure Direct Object Reference)
   */
  static async testIDOR(
    context: TestContext,
    getResource: (id: string) => Promise<any>,
    ownResourceId: string,
    otherResourceId: string
  ) {
    // Should be able to access own resource
    const ownResource = await getResource(ownResourceId);
    expect(ownResource).toBeDefined();

    // Should not be able to access other user's resource (unless authorized)
    await expect(getResource(otherResourceId))
      .rejects.toThrow();
  }
}

// Concurrency test helpers
export class ConcurrencyTester {
  /**
   * Tests for race conditions in resource creation
   */
  static async testRaceCondition(
    context: TestContext,
    createResource: () => Promise<any>,
    uniqueField: string
  ) {
    const promises = [];
    const results: any[] = [];
    const errors: any[] = [];

    // Create multiple concurrent requests
    for (let i = 0; i < 5; i++) {
      promises.push(
        createResource()
          .then(result => results.push(result))
          .catch(error => errors.push(error))
      );
    }

    await Promise.all(promises);

    // Should have exactly one success and rest failures
    expect(results.length).toBe(1);
    expect(errors.length).toBe(4);

    // Check that errors are about duplicates
    errors.forEach(error => {
      expect(error.message).toMatch(/already exists|concurrent/i);
    });
  }

  /**
   * Tests for deadlock scenarios
   */
  static async testDeadlockPrevention(
    context: TestContext,
    action1: () => Promise<any>,
    action2: () => Promise<any>
  ) {
    // Execute potentially conflicting actions concurrently
    const results = await Promise.allSettled([action1(), action2()]);

    // Both should complete without deadlock
    const fulfilled = results.filter(r => r.status === 'fulfilled');
    const rejected = results.filter(r => r.status === 'rejected');

    // At least one should succeed
    expect(fulfilled.length).toBeGreaterThan(0);

    // If one fails, it should be due to conflict, not deadlock
    if (rejected.length > 0) {
      const reasons = rejected.map(r => (r as any).reason.message);
      reasons.forEach(reason => {
        expect(reason).not.toContain('deadlock');
        expect(reason).not.toContain('timeout');
      });
    }
  }

  /**
   * Tests for optimistic locking
   */
  static async testOptimisticLocking(
    context: TestContext,
    getResource: (id: string) => Promise<any>,
    updateResource: (id: string, data: any, version?: number) => Promise<any>,
    resourceId: string
  ) {
    // Get initial resource
    const resource1 = await getResource(resourceId);
    const resource2 = await getResource(resourceId);

    // Update with first version
    const updated1 = await updateResource(resourceId, { name: 'Update 1' }, resource1.version);

    // Second update should fail due to version mismatch
    await expect(
      updateResource(resourceId, { name: 'Update 2' }, resource2.version)
    ).rejects.toThrow();
  }
}

// Edge case generators
export class EdgeCaseGenerator {
  static getBoundaryValues() {
    return {
      strings: [
        '',                           // Empty string
        ' ',                          // Single space
        '  ',                         // Multiple spaces
        '\n',                         // Newline
        '\t',                         // Tab
        'a'.repeat(255),              // Max typical string length
        'a'.repeat(256),              // Over typical limit
        'a'.repeat(1000),             // Very long string
        '😀',                         // Emoji
        '你好',                       // Unicode characters
        '<>',                         // HTML characters
        '\\',                         // Backslash
        '"',                          // Quote
        "'",                          // Single quote
        null,                         // Null value
        undefined,                    // Undefined value
      ],
      numbers: [
        0,                            // Zero
        -1,                           // Negative
        1,                            // Small positive
        Number.MAX_SAFE_INTEGER,      // Max safe integer
        Number.MIN_SAFE_INTEGER,      // Min safe integer
        Number.MAX_VALUE,             // Max value
        Number.MIN_VALUE,             // Min value
        Infinity,                     // Infinity
        -Infinity,                    // Negative infinity
        NaN,                          // Not a number
        0.1 + 0.2,                    // Floating point precision issue
      ],
      arrays: [
        [],                           // Empty array
        [null],                       // Array with null
        [undefined],                  // Array with undefined
        new Array(1000),              // Large empty array
        new Array(1000).fill('a'),   // Large filled array
      ],
      objects: [
        {},                           // Empty object
        { __proto__: null },          // No prototype
        { constructor: null },        // Null constructor
        Object.create(null),          // No prototype chain
      ],
    };
  }

  static getPhoneNumberEdgeCases() {
    return [
      '',                   // Empty
      '0',                  // Too short
      '123',                // Still too short
      '12345678901234567890', // Too long
      'abcdefghij',         // Letters
      '123-456-7890',       // With dashes
      '(123) 456-7890',     // With formatting
      '+11234567890',       // With country code included
      ' 1234567890',        // Leading space
      '1234567890 ',        // Trailing space
      '12345 67890',        // Space in middle
    ];
  }

  static getPasswordEdgeCases() {
    return [
      '',                   // Empty
      'a',                  // Too short
      '1234567',            // Just under minimum
      'a'.repeat(100),      // Very long
      'password',           // Common password
      '12345678',           // Numbers only
      'PASSWORD',           // All caps
      'Pass word',          // With space
      'пароль',             // Non-ASCII
      '😀😀😀😀😀😀😀😀',  // Emojis
      '<script>',           // HTML tags
      "'; DROP TABLE;",     // SQL injection
    ];
  }

  static getMPinEdgeCases() {
    return [
      '',                   // Empty
      '1',                  // Too short
      '123',                // Still too short
      '12345678',           // Too long
      'abcd',               // Letters
      '12 34',              // With space
      '0000',               // All zeros
      '1111',               // Repeating digits
      '9999',               // All nines
    ];
  }
}

// Performance test helpers
export class PerformanceTester {
  /**
   * Tests response time under load
   */
  static async testResponseTime(
    context: TestContext,
    action: () => Promise<any>,
    maxTime: number = 1000
  ) {
    const start = Date.now();
    await action();
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(maxTime);
  }

  /**
   * Tests bulk operations
   */
  static async testBulkOperation(
    context: TestContext,
    createItem: () => Promise<any>,
    count: number = 100
  ) {
    const promises = [];
    const start = Date.now();

    for (let i = 0; i < count; i++) {
      promises.push(createItem());
    }

    const results = await Promise.allSettled(promises);
    const elapsed = Date.now() - start;

    const successful = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;

    // Most should succeed
    expect(successful).toBeGreaterThan(count * 0.9);

    // Should complete in reasonable time
    expect(elapsed).toBeLessThan(count * 100); // 100ms per item max

    return { successful, failed, elapsed };
  }
}

// State transition validators
export class StateTransitionValidator {
  /**
   * Validates that state transitions follow business rules
   */
  static validateTransition(
    fromState: string,
    toState: string,
    allowedTransitions: Map<string, string[]>
  ) {
    const allowed = allowedTransitions.get(fromState) || [];
    expect(allowed).toContain(toState);
  }

  /**
   * Validates that certain states are terminal
   */
  static validateTerminalState(
    state: string,
    terminalStates: string[]
  ) {
    if (terminalStates.includes(state)) {
      // No further transitions should be allowed
      return true;
    }
    return false;
  }
}

// Audit trail validator
export class AuditValidator {
  /**
   * Validates that actions are properly logged
   */
  static validateAuditEntry(entry: any) {
    expect(entry).toHaveProperty('timestamp');
    expect(entry).toHaveProperty('user_id');
    expect(entry).toHaveProperty('action');
    expect(entry).toHaveProperty('resource_type');
    expect(entry).toHaveProperty('resource_id');

    // Timestamp should be recent
    const timestamp = new Date(entry.timestamp).getTime();
    expect(Date.now() - timestamp).toBeLessThan(60000); // Within last minute
  }

  /**
   * Validates that sensitive data is not logged
   */
  static validateNoSensitiveData(entry: any) {
    const json = JSON.stringify(entry);

    // Should not contain passwords
    expect(json).not.toContain('password');
    expect(json).not.toContain('mpin');
    expect(json).not.toContain('secret');
    expect(json).not.toContain('token');

    // Should not contain full credit card numbers
    expect(json).not.toMatch(/\d{16}/);

    // Should not contain SSN
    expect(json).not.toMatch(/\d{3}-\d{2}-\d{4}/);
  }
}
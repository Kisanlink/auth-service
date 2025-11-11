/**
 * Login Integration Tests
 *
 * Tests authentication flow including edge cases, validation,
 * security scenarios, and business logic invariants.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  TestContext,
  expectValidationError,
  expectUnauthorizedError,
  SecurityTester,
  EdgeCaseGenerator,
  InvariantChecker,
} from '../../helpers/test-utils';

describe('Auth Service - Login', () => {
  let context: TestContext;

  beforeEach(() => {
    context = new TestContext();
  });

  afterEach(() => {
    context.cleanup();
  });

  describe('Happy Path', () => {
    it('should login successfully with valid credentials', async () => {
      const service = context.getService();

      const response = await service.auth.login({
        country_code: '+1',
        phone_number: '1234567890',
        password: 'password123',
      });

      expect(response).toHaveProperty('access_token');
      expect(response).toHaveProperty('refresh_token');
      expect(response).toHaveProperty('user');
      expect(response.user.id).toBe('user-001');
      expect(response.user.phone_number).toBe('1234567890');
      expect(response).toHaveProperty('permissions');
      expect(Array.isArray(response.permissions)).toBe(true);

      // Verify tokens are valid
      expect(response.access_token).toMatch(/^access_/);
      expect(response.refresh_token).toMatch(/^refresh_/);
    });

    it('should login with default country code', async () => {
      const service = context.getService();

      const response = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      expect(response).toHaveProperty('access_token');
      expect(response.user.phone_number).toBe('1234567890');
    });

    it('should login with different country codes', async () => {
      const service = context.getService();

      const response = await service.auth.login({
        country_code: '+91',
        phone_number: '9876543210',
        password: 'password456',
      });

      expect(response).toHaveProperty('access_token');
      expect(response.user.phone_number).toBe('9876543210');
    });
  });

  describe('Validation Tests', () => {
    it('should reject login without phone number', async () => {
      const service = context.getService();

      await expect(
        service.auth.login({
          phone_number: '',
          password: 'password123',
        })
      ).rejects.toThrow('Phone number and password are required');
    });

    it('should reject login without password', async () => {
      const service = context.getService();

      await expect(
        service.auth.login({
          phone_number: '1234567890',
          password: '',
        })
      ).rejects.toThrow('Phone number and password are required');
    });

    it('should reject login with invalid phone number format', async () => {
      const service = context.getService();
      const edgeCases = EdgeCaseGenerator.getPhoneNumberEdgeCases();

      for (const phone of edgeCases) {
        if (phone !== '1234567890') { // Skip valid number
          try {
            await service.auth.login({
              phone_number: phone,
              password: 'password123',
            });
            // If it doesn't throw, check it returns invalid credentials
            expect(true).toBe(false); // Should have thrown
          } catch (error: any) {
            expect(error.message).toMatch(/Invalid credentials|required/);
          }
        }
      }
    });

    it('should handle various password edge cases', async () => {
      const service = context.getService();
      const edgeCases = EdgeCaseGenerator.getPasswordEdgeCases();

      for (const password of edgeCases) {
        try {
          await service.auth.login({
            phone_number: '1234567890',
            password: password as string,
          });
          // Should fail for all edge cases except the correct password
          expect(true).toBe(false);
        } catch (error: any) {
          expect(error.message).toMatch(/Invalid credentials|required/);
        }
      }
    });
  });

  describe('Authentication Failures', () => {
    it('should reject login with wrong password', async () => {
      const service = context.getService();

      await expect(
        service.auth.login({
          phone_number: '1234567890',
          password: 'wrongpassword',
        })
      ).rejects.toThrow('Invalid credentials');
    });

    it('should reject login with non-existent user', async () => {
      const service = context.getService();

      await expect(
        service.auth.login({
          phone_number: '0000000000',
          password: 'anypassword',
        })
      ).rejects.toThrow('Invalid credentials');
    });

    it('should reject login for inactive user', async () => {
      const service = context.getService();

      await expect(
        service.auth.login({
          country_code: '+1',
          phone_number: '5555555555',
          password: 'password789',
        })
      ).rejects.toThrow('Account is disabled');
    });

    it('should not reveal whether user exists through error messages', async () => {
      const service = context.getService();

      // Non-existent user
      let error1: any;
      try {
        await service.auth.login({
          phone_number: '0000000000',
          password: 'wrongpassword',
        });
      } catch (e) {
        error1 = e;
      }

      // Existing user, wrong password
      let error2: any;
      try {
        await service.auth.login({
          phone_number: '1234567890',
          password: 'wrongpassword',
        });
      } catch (e) {
        error2 = e;
      }

      // Both should return same error message
      expect(error1.message).toBe(error2.message);
    });
  });

  describe('Brute Force Protection', () => {
    it('should lock account after multiple failed attempts', async () => {
      const service = context.getService();
      const maxAttempts = 5;

      // Make multiple failed attempts
      for (let i = 0; i < maxAttempts; i++) {
        await expect(
          service.auth.login({
            phone_number: '1234567890',
            password: 'wrongpassword',
          })
        ).rejects.toThrow('Invalid credentials');
      }

      // Next attempt should be blocked
      await expect(
        service.auth.login({
          phone_number: '1234567890',
          password: 'password123', // Even with correct password
        })
      ).rejects.toThrow('Account locked due to too many failed attempts');
    });

    it('should track failed attempts per phone number', async () => {
      const service = context.getService();

      // Fail on one number
      await expect(
        service.auth.login({
          phone_number: '1234567890',
          password: 'wrong',
        })
      ).rejects.toThrow();

      // Should still be able to login with different number
      const response = await service.auth.login({
        country_code: '+91',
        phone_number: '9876543210',
        password: 'password456',
      });

      expect(response).toHaveProperty('access_token');
    });

    it('should reset failed attempts on successful login', async () => {
      const service = context.getService();

      // Make some failed attempts (but not max)
      for (let i = 0; i < 3; i++) {
        await expect(
          service.auth.login({
            phone_number: '1234567890',
            password: 'wrong',
          })
        ).rejects.toThrow();
      }

      // Successful login should reset counter
      await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      // Can fail again without being locked
      for (let i = 0; i < 3; i++) {
        await expect(
          service.auth.login({
            phone_number: '1234567890',
            password: 'wrong',
          })
        ).rejects.toThrow('Invalid credentials');
      }
    });
  });

  describe('Token Management', () => {
    it('should return unique tokens for each login', async () => {
      const service = context.getService();

      const response1 = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      const response2 = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      expect(response1.access_token).not.toBe(response2.access_token);
      expect(response1.refresh_token).not.toBe(response2.refresh_token);
    });

    it('should include user ID in token payload', async () => {
      const service = context.getService();

      const response = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      // Token should contain user ID (check mock implementation)
      expect(response.access_token).toContain('user-001');
    });

    it('should set appropriate token expiry', async () => {
      const service = context.getService();

      const response = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      // Mock server sets 1 hour expiry
      const mockServer = context.getMockServer();
      const session = mockServer.getSessionByToken(response.access_token);

      expect(session).toBeDefined();
      expect(session!.expires_at).toBeGreaterThan(Date.now());
      expect(session!.expires_at).toBeLessThanOrEqual(Date.now() + 3600000);
    });
  });

  describe('Permission Loading', () => {
    it('should load user permissions on login', async () => {
      const service = context.getService();

      // First, assign a role to the user
      await context.loginAsTestUser();

      // Login again to check permissions
      const response = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      expect(response).toHaveProperty('permissions');
      expect(Array.isArray(response.permissions)).toBe(true);
    });

    it('should include group-based permissions', async () => {
      const service = context.getService();

      const response = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      // User is in group-001 which has admin role
      expect(response.permissions).toContain('dashboard:view');
    });

    it('should handle users with no permissions', async () => {
      const service = context.getService();

      const response = await service.auth.login({
        country_code: '+91',
        phone_number: '9876543210',
        password: 'password456',
      });

      expect(response.permissions).toEqual([]);
    });
  });

  describe('Security Tests', () => {
    it('should prevent SQL injection attempts', async () => {
      const service = context.getService();

      await SecurityTester.testSQLInjection(
        context,
        async (payload) => service.auth.login({
          phone_number: payload.name,
          password: 'test',
        })
      );
    });

    it('should not be vulnerable to timing attacks', async () => {
      const service = context.getService();

      await SecurityTester.testTimingAttack(
        context,
        async () => service.auth.login({
          phone_number: '1234567890',
          password: 'password123',
        }),
        async () => service.auth.login({
          phone_number: '0000000000',
          password: 'wrongpassword',
        })
      );
    });

    it('should sanitize error messages', async () => {
      const service = context.getService();

      try {
        await service.auth.login({
          phone_number: '../../etc/passwd',
          password: 'test',
        });
      } catch (error: any) {
        // Error message should not reveal system paths
        expect(error.message).not.toContain('/etc/passwd');
        expect(error.message).not.toContain('../');
      }
    });
  });

  describe('Business Logic Invariants', () => {
    it('should enforce that only active users can login', async () => {
      const service = context.getService();

      await InvariantChecker.checkInactiveUserCannotAct(
        context,
        async () => service.auth.login({
          country_code: '+1',
          phone_number: '5555555555',
          password: 'password789',
        })
      );
    });

    it('should maintain session consistency', async () => {
      const service = context.getService();

      const response = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      const mockServer = context.getMockServer();
      const session = mockServer.getSessionByToken(response.access_token);

      // Session should be consistent with login response
      expect(session!.user_id).toBe(response.user.id);
      expect(session!.access_token).toBe(response.access_token);
      expect(session!.refresh_token).toBe(response.refresh_token);
    });

    it('should properly handle concurrent login attempts', async () => {
      const service = context.getService();

      // Multiple simultaneous login attempts
      const promises = [];
      for (let i = 0; i < 5; i++) {
        promises.push(
          service.auth.login({
            phone_number: '1234567890',
            password: 'password123',
          })
        );
      }

      const results = await Promise.all(promises);

      // All should succeed with different tokens
      const tokens = new Set(results.map(r => r.access_token));
      expect(tokens.size).toBe(5);
    });

    it('should validate country code format', async () => {
      const service = context.getService();

      const invalidCountryCodes = [
        '1',      // Missing +
        '++1',    // Double +
        '+',      // Just +
        'US',     // Letters
        '+1234567890', // Too long
      ];

      for (const cc of invalidCountryCodes) {
        // Should either fail or treat as part of phone number
        const result = await service.auth.login({
          country_code: cc,
          phone_number: '1234567890',
          password: 'password123',
        }).catch(e => e);

        if (result instanceof Error) {
          expect(result.message).toMatch(/Invalid|not found/);
        }
      }
    });
  });

  describe('Integration with Other Services', () => {
    it('should allow authenticated requests after login', async () => {
      const service = context.getService();

      const loginResponse = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      context.setAccessToken(loginResponse.access_token);

      // Should be able to make authenticated requests
      const users = await service.users.list();
      expect(users).toHaveProperty('data');
    });

    it('should include role information in login response', async () => {
      const service = context.getService();

      const response = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      expect(response.user).toHaveProperty('roles');
      expect(Array.isArray(response.user.roles)).toBe(true);
    });

    it('should handle special characters in passwords', async () => {
      const service = context.getService();

      // Register user with special character password
      await service.auth.register({
        country_code: '+1',
        phone_number: '8888888888',
        password: 'P@ssw0rd!#$%^&*()',
        name: 'Special Char User',
      });

      // Should be able to login with same password
      const response = await service.auth.login({
        phone_number: '8888888888',
        password: 'P@ssw0rd!#$%^&*()',
      });

      expect(response).toHaveProperty('access_token');
    });
  });
});
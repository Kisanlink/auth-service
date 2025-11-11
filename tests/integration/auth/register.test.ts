/**
 * Registration Integration Tests
 *
 * Tests user registration including validation, duplicate prevention,
 * concurrent registration, and security scenarios.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  TestContext,
  expectValidationError,
  expectConflictError,
  generatePhoneNumber,
  generateName,
  EdgeCaseGenerator,
  SecurityTester,
  ConcurrencyTester,
  InvariantChecker,
} from '../../helpers/test-utils';

describe('Auth Service - Register', () => {
  let context: TestContext;

  beforeEach(() => {
    context = new TestContext();
  });

  afterEach(() => {
    context.cleanup();
  });

  describe('Happy Path', () => {
    it('should register new user successfully', async () => {
      const service = context.getService();
      const phoneNumber = generatePhoneNumber();

      const response = await service.auth.register({
        country_code: '+1',
        phone_number: phoneNumber,
        password: 'SecurePass123!',
        name: 'New User',
      });

      expect(response).toHaveProperty('access_token');
      expect(response).toHaveProperty('refresh_token');
      expect(response).toHaveProperty('user');
      expect(response.user.phone_number).toBe(phoneNumber);
      expect(response.user.name).toBe('New User');
      expect(response.user.id).toMatch(/^user-/);
    });

    it('should auto-login after registration', async () => {
      const service = context.getService();
      const phoneNumber = generatePhoneNumber();

      const response = await service.auth.register({
        country_code: '+1',
        phone_number: phoneNumber,
        password: 'SecurePass123!',
      });

      // Should receive tokens immediately
      expect(response.access_token).toBeDefined();
      expect(response.refresh_token).toBeDefined();

      // Token should be valid for authenticated requests
      context.setAccessToken(response.access_token);
      const users = await service.users.list();
      expect(users).toHaveProperty('data');
    });

    it('should register without name (optional field)', async () => {
      const service = context.getService();
      const phoneNumber = generatePhoneNumber();

      const response = await service.auth.register({
        country_code: '+1',
        phone_number: phoneNumber,
        password: 'SecurePass123!',
      });

      expect(response.user.name).toBeUndefined();
      expect(response.user.phone_number).toBe(phoneNumber);
    });

    it('should register with different country codes', async () => {
      const service = context.getService();

      const testCases = [
        { code: '+1', phone: generatePhoneNumber() },
        { code: '+91', phone: generatePhoneNumber() },
        { code: '+44', phone: generatePhoneNumber() },
        { code: '+86', phone: generatePhoneNumber() },
      ];

      for (const tc of testCases) {
        const response = await service.auth.register({
          country_code: tc.code,
          phone_number: tc.phone,
          password: 'SecurePass123!',
        });

        expect(response.user.phone_number).toBe(tc.phone);
      }
    });
  });

  describe('Validation Tests', () => {
    it('should reject registration without phone number', async () => {
      const service = context.getService();

      await expect(
        service.auth.register({
          country_code: '+1',
          phone_number: '',
          password: 'SecurePass123!',
        })
      ).rejects.toThrow('Phone number and password are required');
    });

    it('should reject registration without password', async () => {
      const service = context.getService();

      await expect(
        service.auth.register({
          country_code: '+1',
          phone_number: generatePhoneNumber(),
          password: '',
        })
      ).rejects.toThrow('Phone number and password are required');
    });

    it('should validate password strength', async () => {
      const service = context.getService();
      const phoneNumber = generatePhoneNumber();

      // Too short
      await expect(
        service.auth.register({
          phone_number: phoneNumber,
          password: 'short',
        })
      ).rejects.toThrow('Password must be at least 8 characters');

      // Minimum length
      const response = await service.auth.register({
        phone_number: generatePhoneNumber(),
        password: '12345678',
      });
      expect(response).toHaveProperty('access_token');
    });

    it('should validate phone number format', async () => {
      const service = context.getService();

      // Invalid format
      await expect(
        service.auth.register({
          phone_number: '123',
          password: 'SecurePass123!',
        })
      ).rejects.toThrow('Invalid phone number format');

      // Letters in phone number
      await expect(
        service.auth.register({
          phone_number: 'abcdefghij',
          password: 'SecurePass123!',
        })
      ).rejects.toThrow('Invalid phone number format');

      // Special characters
      await expect(
        service.auth.register({
          phone_number: '123-456-7890',
          password: 'SecurePass123!',
        })
      ).rejects.toThrow('Invalid phone number format');
    });

    it('should handle all phone number edge cases', async () => {
      const service = context.getService();
      const edgeCases = EdgeCaseGenerator.getPhoneNumberEdgeCases();

      for (const phone of edgeCases) {
        // Only 10-digit numbers should pass
        if (/^\d{10}$/.test(phone)) {
          const response = await service.auth.register({
            phone_number: phone,
            password: 'SecurePass123!',
          });
          expect(response).toHaveProperty('access_token');
        } else {
          await expect(
            service.auth.register({
              phone_number: phone,
              password: 'SecurePass123!',
            })
          ).rejects.toThrow();
        }
      }
    });

    it('should handle all password edge cases', async () => {
      const service = context.getService();
      const edgeCases = EdgeCaseGenerator.getPasswordEdgeCases();

      for (const password of edgeCases) {
        const phoneNumber = generatePhoneNumber();

        if (typeof password === 'string' && password.length >= 8) {
          // Should accept if length is valid
          const response = await service.auth.register({
            phone_number: phoneNumber,
            password: password,
          });
          expect(response).toHaveProperty('access_token');
        } else {
          await expect(
            service.auth.register({
              phone_number: phoneNumber,
              password: password as string,
            })
          ).rejects.toThrow();
        }
      }
    });
  });

  describe('Duplicate Prevention', () => {
    it('should prevent duplicate phone numbers', async () => {
      const service = context.getService();
      const phoneNumber = generatePhoneNumber();

      // First registration
      await service.auth.register({
        country_code: '+1',
        phone_number: phoneNumber,
        password: 'SecurePass123!',
      });

      // Duplicate attempt
      await expect(
        service.auth.register({
          country_code: '+1',
          phone_number: phoneNumber,
          password: 'DifferentPass456!',
        })
      ).rejects.toThrow('User with this phone number already exists');
    });

    it('should allow same phone number with different country code', async () => {
      const service = context.getService();
      const phoneNumber = generatePhoneNumber();

      // First registration
      await service.auth.register({
        country_code: '+1',
        phone_number: phoneNumber,
        password: 'SecurePass123!',
      });

      // Same number, different country
      const response = await service.auth.register({
        country_code: '+91',
        phone_number: phoneNumber,
        password: 'SecurePass123!',
      });

      expect(response).toHaveProperty('access_token');
    });

    it('should check existing users case-insensitively', async () => {
      const service = context.getService();

      // Register existing user (from seed data)
      await expect(
        service.auth.register({
          country_code: '+1',
          phone_number: '1234567890', // Already exists in mock
          password: 'NewPassword123!',
        })
      ).rejects.toThrow('already exists');
    });
  });

  describe('Concurrent Registration', () => {
    it('should handle concurrent registration attempts with same phone', async () => {
      const service = context.getService();
      const phoneNumber = generatePhoneNumber();

      await ConcurrencyTester.testRaceCondition(
        context,
        async () => service.auth.register({
          country_code: '+1',
          phone_number: phoneNumber,
          password: 'SecurePass123!',
          name: 'Concurrent User',
        }),
        'phone_number'
      );
    });

    it('should detect and prevent race conditions', async () => {
      const service = context.getService();
      const phoneNumber = generatePhoneNumber();

      // Simulate rapid concurrent requests
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(
          service.auth.register({
            country_code: '+1',
            phone_number: phoneNumber,
            password: 'SecurePass123!',
          }).catch(e => e)
        );
      }

      const results = await Promise.all(promises);

      // Count successes and failures
      const successes = results.filter(r => !(r instanceof Error));
      const failures = results.filter(r => r instanceof Error);

      // Exactly one should succeed
      expect(successes.length).toBe(1);
      expect(failures.length).toBe(9);

      // Failures should mention concurrency or duplication
      failures.forEach((error: any) => {
        expect(error.message).toMatch(/already exists|concurrent/i);
      });
    });

    it('should allow concurrent registration with different phones', async () => {
      const service = context.getService();

      // Different phone numbers should all succeed
      const promises = [];
      for (let i = 0; i < 5; i++) {
        promises.push(
          service.auth.register({
            country_code: '+1',
            phone_number: generatePhoneNumber(),
            password: 'SecurePass123!',
          })
        );
      }

      const results = await Promise.all(promises);

      // All should succeed
      results.forEach(result => {
        expect(result).toHaveProperty('access_token');
      });

      // All should have unique user IDs
      const userIds = new Set(results.map(r => r.user.id));
      expect(userIds.size).toBe(5);
    });
  });

  describe('Security Tests', () => {
    it('should prevent SQL injection in registration', async () => {
      const service = context.getService();

      await SecurityTester.testSQLInjection(
        context,
        async (payload) => service.auth.register({
          phone_number: generatePhoneNumber(),
          password: 'SecurePass123!',
          name: payload.name,
        })
      );
    });

    it('should sanitize user input', async () => {
      const service = context.getService();

      await SecurityTester.testXSS(
        context,
        async (payload) => service.auth.register({
          phone_number: generatePhoneNumber(),
          password: 'SecurePass123!',
          name: payload.name,
        })
      );
    });

    it('should not expose sensitive data in errors', async () => {
      const service = context.getService();

      try {
        await service.auth.register({
          phone_number: '1234567890', // Existing user
          password: 'NewPass123!',
        });
      } catch (error: any) {
        // Should not reveal password or other sensitive info
        expect(error.message).not.toContain('password');
        expect(error.message).not.toContain('NewPass123');
      }
    });

    it('should handle malformed requests gracefully', async () => {
      const service = context.getService();

      // Missing required fields
      await expect(
        service.auth.register({} as any)
      ).rejects.toThrow();

      // Invalid types
      await expect(
        service.auth.register({
          phone_number: 12345 as any,
          password: true as any,
        })
      ).rejects.toThrow();

      // Null values
      await expect(
        service.auth.register({
          phone_number: null as any,
          password: null as any,
        })
      ).rejects.toThrow();
    });
  });

  describe('Business Logic Invariants', () => {
    it('should create active users by default', async () => {
      const service = context.getService();
      const phoneNumber = generatePhoneNumber();

      const response = await service.auth.register({
        phone_number: phoneNumber,
        password: 'SecurePass123!',
      });

      // User should be able to login immediately
      const loginResponse = await service.auth.login({
        phone_number: phoneNumber,
        password: 'SecurePass123!',
      });

      expect(loginResponse).toHaveProperty('access_token');
    });

    it('should initialize users with empty permissions', async () => {
      const service = context.getService();

      const response = await service.auth.register({
        phone_number: generatePhoneNumber(),
        password: 'SecurePass123!',
      });

      expect(response.permissions).toEqual([]);
    });

    it('should generate unique user IDs', async () => {
      const service = context.getService();

      const responses = [];
      for (let i = 0; i < 10; i++) {
        const response = await service.auth.register({
          phone_number: generatePhoneNumber(),
          password: 'SecurePass123!',
        });
        responses.push(response);
      }

      const userIds = responses.map(r => r.user.id);
      const uniqueIds = new Set(userIds);

      expect(uniqueIds.size).toBe(10);
    });

    it('should set timestamps correctly', async () => {
      const service = context.getService();

      const beforeTime = Date.now();

      const response = await service.auth.register({
        phone_number: generatePhoneNumber(),
        password: 'SecurePass123!',
      });

      const afterTime = Date.now();

      // Get user details
      context.setAccessToken(response.access_token);
      const userDetails = await service.users.getById(response.user.id);

      const createdAt = new Date(userDetails.created_at).getTime();
      const updatedAt = new Date(userDetails.updated_at).getTime();

      expect(createdAt).toBeGreaterThanOrEqual(beforeTime);
      expect(createdAt).toBeLessThanOrEqual(afterTime);
      expect(updatedAt).toBe(createdAt); // Should be same on creation
    });

    it('should validate phone uniqueness per country code', async () => {
      const service = context.getService();
      const phoneNumber = generatePhoneNumber();

      // Register with +1
      await service.auth.register({
        country_code: '+1',
        phone_number: phoneNumber,
        password: 'SecurePass123!',
      });

      // Should check uniqueness including country code
      await InvariantChecker.checkPhoneNumberUniqueness(
        context,
        '+1',
        phoneNumber
      );
    });
  });

  describe('Data Integrity', () => {
    it('should store user data correctly', async () => {
      const service = context.getService();
      const phoneNumber = generatePhoneNumber();
      const name = generateName();

      const response = await service.auth.register({
        country_code: '+91',
        phone_number: phoneNumber,
        password: 'SecurePass123!',
        name: name,
      });

      // Verify stored data
      context.setAccessToken(response.access_token);
      const user = await service.users.getById(response.user.id);

      expect(user.phone_number).toBe(phoneNumber);
      expect(user.country_code).toBe('+91');
      expect(user.name).toBe(name);
    });

    it('should handle special characters in names', async () => {
      const service = context.getService();

      const specialNames = [
        "O'Brien",
        "Mary-Jane",
        "José María",
        "François",
        "Müller",
        "李明",
        "محمد",
      ];

      for (const name of specialNames) {
        const response = await service.auth.register({
          phone_number: generatePhoneNumber(),
          password: 'SecurePass123!',
          name: name,
        });

        expect(response.user.name).toBe(name);
      }
    });

    it('should trim whitespace from inputs', async () => {
      const service = context.getService();
      const phoneNumber = generatePhoneNumber();

      const response = await service.auth.register({
        phone_number: ` ${phoneNumber} `,
        password: ' SecurePass123! ',
        name: '  Test User  ',
      });

      // Should trim whitespace
      expect(response.user.phone_number).toBe(phoneNumber);
      expect(response.user.name).toBe('Test User');
    });
  });

  describe('Integration Points', () => {
    it('should be immediately usable for authentication', async () => {
      const service = context.getService();
      const phoneNumber = generatePhoneNumber();

      const regResponse = await service.auth.register({
        phone_number: phoneNumber,
        password: 'SecurePass123!',
      });

      // Use token for authenticated request
      context.setAccessToken(regResponse.access_token);

      const users = await service.users.list();
      expect(users.data).toBeDefined();
    });

    it('should appear in user listings after registration', async () => {
      const service = context.getService();
      const phoneNumber = generatePhoneNumber();
      const name = generateName();

      // Login as admin first
      await context.loginAsTestUser();

      // Register new user
      const regResponse = await service.auth.register({
        phone_number: phoneNumber,
        password: 'SecurePass123!',
        name: name,
      });

      // Check user appears in list
      const users = await service.users.list();
      const newUser = users.data.find((u: any) => u.id === regResponse.user.id);

      expect(newUser).toBeDefined();
      expect(newUser.name).toBe(name);
      expect(newUser.phone_number).toBe(phoneNumber);
    });
  });
});
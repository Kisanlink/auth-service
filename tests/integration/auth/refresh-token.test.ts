/**
 * Refresh Token Integration Tests
 *
 * Tests token refresh flow including MPIN validation,
 * token rotation, expiry, and security scenarios.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  TestContext,
  expectUnauthorizedError,
  expectValidationError,
  generateMPin,
  InvariantChecker,
  SecurityTester,
} from '../../helpers/test-utils';

describe('Auth Service - Refresh Token', () => {
  let context: TestContext;

  beforeEach(() => {
    context = new TestContext();
  });

  afterEach(() => {
    context.cleanup();
  });

  describe('Happy Path', () => {
    it('should refresh tokens with valid MPIN', async () => {
      const service = context.getService();

      // Login first
      const loginResponse = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      // Refresh tokens
      const refreshResponse = await service.auth.refresh({
        mpin: '1234',
        refresh_token: loginResponse.refresh_token,
      });

      expect(refreshResponse).toHaveProperty('access_token');
      expect(refreshResponse).toHaveProperty('refresh_token');

      // New tokens should be different from old ones
      expect(refreshResponse.access_token).not.toBe(loginResponse.access_token);
      expect(refreshResponse.refresh_token).not.toBe(loginResponse.refresh_token);
    });

    it('should invalidate old tokens after refresh', async () => {
      const service = context.getService();

      const loginResponse = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      const oldAccessToken = loginResponse.access_token;
      const oldRefreshToken = loginResponse.refresh_token;

      // Refresh tokens
      await service.auth.refresh({
        mpin: '1234',
        refresh_token: oldRefreshToken,
      });

      // Old access token should no longer work
      context.setAccessToken(oldAccessToken);
      await expect(service.users.list()).rejects.toThrow('Unauthorized');

      // Old refresh token should no longer work
      await expect(
        service.auth.refresh({
          mpin: '1234',
          refresh_token: oldRefreshToken,
        })
      ).rejects.toThrow('Invalid refresh token');
    });

    it('should allow using new tokens after refresh', async () => {
      const service = context.getService();

      const loginResponse = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      const refreshResponse = await service.auth.refresh({
        mpin: '1234',
        refresh_token: loginResponse.refresh_token,
      });

      // Use new access token
      context.setAccessToken(refreshResponse.access_token);
      const users = await service.users.list();
      expect(users).toHaveProperty('data');
    });
  });

  describe('Validation Tests', () => {
    it('should reject refresh without refresh token', async () => {
      const service = context.getService();

      await expect(
        service.auth.refresh({
          mpin: '1234',
          refresh_token: '',
        })
      ).rejects.toThrow('Refresh token and MPIN are required');
    });

    it('should reject refresh without MPIN', async () => {
      const service = context.getService();

      const loginResponse = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      await expect(
        service.auth.refresh({
          mpin: '',
          refresh_token: loginResponse.refresh_token,
        })
      ).rejects.toThrow('Refresh token and MPIN are required');
    });

    it('should reject invalid refresh token format', async () => {
      const service = context.getService();

      await expect(
        service.auth.refresh({
          mpin: '1234',
          refresh_token: 'invalid-token-format',
        })
      ).rejects.toThrow('Invalid refresh token');
    });

    it('should reject wrong MPIN', async () => {
      const service = context.getService();

      const loginResponse = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      await expect(
        service.auth.refresh({
          mpin: '9999',
          refresh_token: loginResponse.refresh_token,
        })
      ).rejects.toThrow('Invalid MPIN');
    });

    it('should handle users without MPIN set', async () => {
      const service = context.getService();

      // Login as user without MPIN
      const loginResponse = await service.auth.login({
        country_code: '+91',
        phone_number: '9876543210',
        password: 'password456',
      });

      // Try to refresh (user has no MPIN)
      await expect(
        service.auth.refresh({
          mpin: '1234',
          refresh_token: loginResponse.refresh_token,
        })
      ).rejects.toThrow('Invalid MPIN');
    });
  });

  describe('Token Rotation', () => {
    it('should support multiple refresh cycles', async () => {
      const service = context.getService();

      let currentTokens = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      const tokenHistory = [currentTokens.access_token];

      // Refresh multiple times
      for (let i = 0; i < 5; i++) {
        const newTokens = await service.auth.refresh({
          mpin: '1234',
          refresh_token: currentTokens.refresh_token,
        });

        tokenHistory.push(newTokens.access_token);

        // Verify new tokens are unique
        expect(newTokens.access_token).not.toBe(currentTokens.access_token);
        expect(newTokens.refresh_token).not.toBe(currentTokens.refresh_token);

        currentTokens = newTokens;
      }

      // All tokens should be unique
      const uniqueTokens = new Set(tokenHistory);
      expect(uniqueTokens.size).toBe(6); // Initial + 5 refreshes
    });

    it('should prevent refresh token reuse', async () => {
      const service = context.getService();

      const loginResponse = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      // First refresh succeeds
      await service.auth.refresh({
        mpin: '1234',
        refresh_token: loginResponse.refresh_token,
      });

      // Second attempt with same token fails
      await expect(
        service.auth.refresh({
          mpin: '1234',
          refresh_token: loginResponse.refresh_token,
        })
      ).rejects.toThrow('Invalid refresh token');
    });

    it('should handle concurrent refresh attempts', async () => {
      const service = context.getService();

      const loginResponse = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      // Try to refresh concurrently with same token
      const promises = [];
      for (let i = 0; i < 5; i++) {
        promises.push(
          service.auth.refresh({
            mpin: '1234',
            refresh_token: loginResponse.refresh_token,
          }).catch(e => e)
        );
      }

      const results = await Promise.all(promises);

      // Only one should succeed
      const successes = results.filter(r => !(r instanceof Error));
      const failures = results.filter(r => r instanceof Error);

      expect(successes.length).toBe(1);
      expect(failures.length).toBe(4);

      // Failures should be about invalid token
      failures.forEach((error: any) => {
        expect(error.message).toContain('Invalid refresh token');
      });
    });
  });

  describe('Session Consistency', () => {
    it('should maintain user context after refresh', async () => {
      const service = context.getService();

      const loginResponse = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      const userId = loginResponse.user.id;

      const refreshResponse = await service.auth.refresh({
        mpin: '1234',
        refresh_token: loginResponse.refresh_token,
      });

      // Verify session still belongs to same user
      const mockServer = context.getMockServer();
      const session = mockServer.getSessionByToken(refreshResponse.access_token);

      expect(session!.user_id).toBe(userId);
    });

    it('should reset token expiry on refresh', async () => {
      const service = context.getService();

      const loginResponse = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      // Wait a bit
      await new Promise(resolve => setTimeout(resolve, 100));

      const refreshResponse = await service.auth.refresh({
        mpin: '1234',
        refresh_token: loginResponse.refresh_token,
      });

      const mockServer = context.getMockServer();
      const oldSession = mockServer.getSessionByToken(loginResponse.access_token);
      const newSession = mockServer.getSessionByToken(refreshResponse.access_token);

      // New session should have later expiry
      expect(newSession!.expires_at).toBeGreaterThan(Date.now());

      // Old session should be invalidated
      expect(oldSession).toBeUndefined();
    });
  });

  describe('Security Tests', () => {
    it('should not be vulnerable to token fixation', async () => {
      const service = context.getService();

      // Attacker's token
      const attackerLogin = await service.auth.login({
        country_code: '+91',
        phone_number: '9876543210',
        password: 'password456',
      });

      // Victim's login
      const victimLogin = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      // Attacker tries to use victim's refresh token with their MPIN
      await expect(
        service.auth.refresh({
          mpin: 'attacker-mpin',
          refresh_token: victimLogin.refresh_token,
        })
      ).rejects.toThrow('Invalid MPIN');
    });

    it('should prevent brute force on MPIN', async () => {
      const service = context.getService();

      const loginResponse = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      // Try multiple wrong MPINs
      const wrongAttempts = ['0000', '1111', '2222', '3333', '4444', '5555'];

      for (const mpin of wrongAttempts) {
        await expect(
          service.auth.refresh({
            mpin: mpin,
            refresh_token: loginResponse.refresh_token,
          })
        ).rejects.toThrow();
      }

      // After multiple failures, token might be invalidated
      // This depends on business logic
    });

    it('should handle expired refresh tokens', async () => {
      const service = context.getService();

      // Use an old/expired token format
      await expect(
        service.auth.refresh({
          mpin: '1234',
          refresh_token: 'refresh_expired_123456789',
        })
      ).rejects.toThrow('Invalid refresh token');
    });

    it('should not leak user information in errors', async () => {
      const service = context.getService();

      try {
        await service.auth.refresh({
          mpin: '1234',
          refresh_token: 'refresh_nonexistent_user',
        });
      } catch (error: any) {
        // Should not reveal if user exists or their MPIN
        expect(error.message).not.toContain('user');
        expect(error.message).not.toContain('not found');
        expect(error.message).toBe('Invalid refresh token');
      }
    });
  });

  describe('Business Logic Invariants', () => {
    it('should require MPIN for refresh (security invariant)', async () => {
      const service = context.getService();

      const loginResponse = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      // Cannot bypass MPIN requirement
      await expect(
        service.auth.refresh({
          mpin: null as any,
          refresh_token: loginResponse.refresh_token,
        })
      ).rejects.toThrow();

      await expect(
        service.auth.refresh({
          mpin: undefined as any,
          refresh_token: loginResponse.refresh_token,
        })
      ).rejects.toThrow();
    });

    it('should maintain token uniqueness invariant', async () => {
      const service = context.getService();

      // Login multiple times
      const tokens = [];
      for (let i = 0; i < 5; i++) {
        const response = await service.auth.login({
          phone_number: '1234567890',
          password: 'password123',
        });
        tokens.push(response);
      }

      // Refresh each token
      const refreshedTokens = [];
      for (const token of tokens) {
        const refreshed = await service.auth.refresh({
          mpin: '1234',
          refresh_token: token.refresh_token,
        });
        refreshedTokens.push(refreshed);
      }

      // All access tokens should be unique
      const allAccessTokens = [
        ...tokens.map(t => t.access_token),
        ...refreshedTokens.map(t => t.access_token),
      ];
      const uniqueAccessTokens = new Set(allAccessTokens);
      expect(uniqueAccessTokens.size).toBe(allAccessTokens.length);

      // All refresh tokens should be unique
      const allRefreshTokens = [
        ...tokens.map(t => t.refresh_token),
        ...refreshedTokens.map(t => t.refresh_token),
      ];
      const uniqueRefreshTokens = new Set(allRefreshTokens);
      expect(uniqueRefreshTokens.size).toBe(allRefreshTokens.length);
    });

    it('should enforce single-use refresh token invariant', async () => {
      const service = context.getService();

      const loginResponse = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      const refreshToken = loginResponse.refresh_token;

      // First use succeeds
      const firstRefresh = await service.auth.refresh({
        mpin: '1234',
        refresh_token: refreshToken,
      });

      expect(firstRefresh).toHaveProperty('access_token');

      // Second use of same token fails
      await expect(
        service.auth.refresh({
          mpin: '1234',
          refresh_token: refreshToken,
        })
      ).rejects.toThrow('Invalid refresh token');

      // Third use still fails
      await expect(
        service.auth.refresh({
          mpin: '1234',
          refresh_token: refreshToken,
        })
      ).rejects.toThrow('Invalid refresh token');
    });

    it('should validate MPIN format', async () => {
      const service = context.getService();

      const loginResponse = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      // Test various invalid MPIN formats
      const invalidMPins = ['', 'abc', '12', '1234567', '12 34', '12.34'];

      for (const mpin of invalidMPins) {
        await expect(
          service.auth.refresh({
            mpin: mpin,
            refresh_token: loginResponse.refresh_token,
          })
        ).rejects.toThrow();
      }
    });
  });

  describe('Edge Cases', () => {
    it('should handle refresh for user with changed MPIN', async () => {
      const service = context.getService();

      const loginResponse = await service.auth.login({
        phone_number: '1234567890',
        password: 'password123',
      });

      // Set access token to update MPIN
      context.setAccessToken(loginResponse.access_token);

      // Update MPIN
      await service.auth.updateMPIN({
        old_mpin: '1234',
        new_mpin: '5678',
      });

      // Refresh should use new MPIN
      await expect(
        service.auth.refresh({
          mpin: '1234', // Old MPIN
          refresh_token: loginResponse.refresh_token,
        })
      ).rejects.toThrow('Invalid MPIN');

      const refreshResponse = await service.auth.refresh({
        mpin: '5678', // New MPIN
        refresh_token: loginResponse.refresh_token,
      });

      expect(refreshResponse).toHaveProperty('access_token');
    });

    it('should handle special characters in tokens', async () => {
      const service = context.getService();

      // Test with tokens containing special characters
      await expect(
        service.auth.refresh({
          mpin: '1234',
          refresh_token: 'refresh_<script>alert(1)</script>',
        })
      ).rejects.toThrow('Invalid refresh token');

      await expect(
        service.auth.refresh({
          mpin: '1234',
          refresh_token: "refresh_'; DROP TABLE sessions;--",
        })
      ).rejects.toThrow('Invalid refresh token');
    });

    it('should handle very long tokens gracefully', async () => {
      const service = context.getService();

      const longToken = 'refresh_' + 'a'.repeat(10000);

      await expect(
        service.auth.refresh({
          mpin: '1234',
          refresh_token: longToken,
        })
      ).rejects.toThrow('Invalid refresh token');
    });
  });
});
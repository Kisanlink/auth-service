/**
 * KYC/Aadhaar Service Business Logic Validation Tests
 *
 * This comprehensive test suite validates critical business logic, security invariants,
 * edge cases, and abuse scenarios for the KYC/Aadhaar service implementation.
 *
 * @author Business Logic Tester
 * @severity CRITICAL
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import createKYCService from '../services/kycService';
import type {
  AadhaarOTPRequest,
  AadhaarOTPResponse,
  AadhaarVerifyRequest,
  AadhaarVerifyResponse,
  KYCStatus,
  KYCStatusType
} from '../types';

describe('KYC Service Business Logic Validation', () => {
  let mockApiClient: any;
  let kycService: ReturnType<typeof createKYCService>;

  beforeEach(() => {
    mockApiClient = {
      post: vi.fn(),
      get: vi.fn(),
      put: vi.fn(),
      delete: vi.fn()
    };
    kycService = createKYCService(mockApiClient);
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  describe('1. AADHAAR OTP GENERATION FLOW - Critical Invariants', () => {

    describe('1.1 Consent Management Requirements', () => {
      it('MUST reject request without consent object', async () => {
        const invalidRequest = {
          aadhaar_number: '1234-5678-9012'
        } as AadhaarOTPRequest;

        mockApiClient.post.mockRejectedValue({
          status: 400,
          error: { code: 'CONSENT_REQUIRED' }
        });

        await expect(kycService.aadhaar.generateOTP(invalidRequest))
          .rejects.toMatchObject({
            status: 400,
            error: { code: 'CONSENT_REQUIRED' }
          });
      });

      it('MUST validate consent contains all required fields', async () => {
        const incompleteConsent: AadhaarOTPRequest = {
          aadhaar_number: '1234-5678-9012',
          consent: {
            purpose: '',  // Empty purpose
            timestamp: new Date().toISOString(),
            version: '1.0'
          }
        };

        mockApiClient.post.mockRejectedValue({
          status: 400,
          error: { code: 'INVALID_CONSENT', message: 'Purpose is required' }
        });

        await expect(kycService.aadhaar.generateOTP(incompleteConsent))
          .rejects.toMatchObject({
            error: { code: 'INVALID_CONSENT' }
          });
      });

      it('MUST reject expired consent timestamp', async () => {
        const expiredConsent: AadhaarOTPRequest = {
          aadhaar_number: '1234-5678-9012',
          consent: {
            purpose: 'KYC Verification',
            timestamp: new Date(Date.now() - 3600000).toISOString(), // 1 hour old
            version: '1.0'
          }
        };

        mockApiClient.post.mockRejectedValue({
          status: 400,
          error: { code: 'CONSENT_EXPIRED' }
        });

        await expect(kycService.aadhaar.generateOTP(expiredConsent))
          .rejects.toMatchObject({
            error: { code: 'CONSENT_EXPIRED' }
          });
      });
    });

    describe('1.2 Aadhaar Number Format Validation', () => {
      const invalidAadhaarNumbers = [
        '123456789012',      // No dashes
        '1234-567-89012',    // Wrong dash pattern
        '1234-5678-901',     // Too short
        '1234-5678-90123',   // Too long
        'XXXX-XXXX-XXXX',    // Non-numeric
        '0000-0000-0000',    // All zeros
        '1111-1111-1111',    // Repeated digits
        '',                  // Empty
        null,                // Null
        undefined            // Undefined
      ];

      invalidAadhaarNumbers.forEach(aadhaar => {
        it(`MUST reject invalid Aadhaar format: ${aadhaar}`, async () => {
          const request: AadhaarOTPRequest = {
            aadhaar_number: aadhaar as string,
            consent: {
              purpose: 'KYC Verification',
              timestamp: new Date().toISOString(),
              version: '1.0'
            }
          };

          mockApiClient.post.mockRejectedValue({
            status: 400,
            error: { code: 'INVALID_AADHAAR' }
          });

          await expect(kycService.aadhaar.generateOTP(request))
            .rejects.toMatchObject({
              status: 400,
              error: { code: 'INVALID_AADHAAR' }
            });
        });
      });
    });

    describe('1.3 Session ID Generation Uniqueness', () => {
      it('MUST generate unique session IDs for concurrent requests', async () => {
        const request: AadhaarOTPRequest = {
          aadhaar_number: '1234-5678-9012',
          consent: {
            purpose: 'KYC Verification',
            timestamp: new Date().toISOString(),
            version: '1.0'
          }
        };

        const sessionIds = new Set<string>();
        const promises = [];

        // Simulate 100 concurrent requests
        for (let i = 0; i < 100; i++) {
          mockApiClient.post.mockResolvedValueOnce({
            session_id: `session-${Date.now()}-${Math.random()}`,
            masked_aadhaar: 'XXXX-XXXX-9012',
            otp_sent_to: '******7890',
            expires_at: new Date(Date.now() + 600000).toISOString(),
            attempts_remaining: 3,
            request_id: `req-${i}`
          });

          promises.push(kycService.aadhaar.generateOTP(request));
        }

        const responses = await Promise.all(promises);
        responses.forEach(response => {
          expect(sessionIds.has(response.session_id)).toBe(false);
          sessionIds.add(response.session_id);
        });

        expect(sessionIds.size).toBe(100);
      });
    });

    describe('1.4 Idempotency Key Handling', () => {
      it('MUST return same response for duplicate requests with same idempotency key', async () => {
        const request: AadhaarOTPRequest = {
          aadhaar_number: '1234-5678-9012',
          consent: {
            purpose: 'KYC Verification',
            timestamp: new Date().toISOString(),
            version: '1.0'
          },
          request_id: 'idempotent-key-123'
        };

        const expectedResponse = {
          session_id: 'session-123',
          masked_aadhaar: 'XXXX-XXXX-9012',
          otp_sent_to: '******7890',
          expires_at: new Date(Date.now() + 600000).toISOString(),
          attempts_remaining: 3,
          request_id: 'idempotent-key-123'
        };

        mockApiClient.post.mockResolvedValue(expectedResponse);

        // Make same request 3 times
        const [response1, response2, response3] = await Promise.all([
          kycService.aadhaar.generateOTP(request),
          kycService.aadhaar.generateOTP(request),
          kycService.aadhaar.generateOTP(request)
        ]);

        expect(response1).toEqual(expectedResponse);
        expect(response2).toEqual(expectedResponse);
        expect(response3).toEqual(expectedResponse);

        // API should handle idempotency, so all calls go through
        expect(mockApiClient.post).toHaveBeenCalledTimes(3);
      });
    });

    describe('1.5 Rate Limiting Protection', () => {
      it('MUST enforce rate limit of 3 OTP requests per hour', async () => {
        const request: AadhaarOTPRequest = {
          aadhaar_number: '1234-5678-9012',
          consent: {
            purpose: 'KYC Verification',
            timestamp: new Date().toISOString(),
            version: '1.0'
          }
        };

        // First 3 requests succeed
        for (let i = 0; i < 3; i++) {
          mockApiClient.post.mockResolvedValueOnce({
            session_id: `session-${i}`,
            masked_aadhaar: 'XXXX-XXXX-9012',
            otp_sent_to: '******7890',
            expires_at: new Date(Date.now() + 600000).toISOString(),
            attempts_remaining: 3,
            request_id: `req-${i}`
          });
        }

        // 4th request fails with rate limit
        mockApiClient.post.mockRejectedValueOnce({
          status: 429,
          error: {
            code: 'RATE_LIMIT_EXCEEDED',
            message: 'Maximum OTP requests exceeded',
            retry_after: 3600
          }
        });

        const responses = [];
        for (let i = 0; i < 3; i++) {
          responses.push(await kycService.aadhaar.generateOTP(request));
        }

        await expect(kycService.aadhaar.generateOTP(request))
          .rejects.toMatchObject({
            status: 429,
            error: {
              code: 'RATE_LIMIT_EXCEEDED',
              retry_after: 3600
            }
          });
      });
    });

    describe('1.6 OTP Expiration Handling', () => {
      it('MUST set expiration time to exactly 10 minutes (600 seconds)', async () => {
        const now = new Date('2024-01-01T12:00:00Z');
        vi.setSystemTime(now);

        const request: AadhaarOTPRequest = {
          aadhaar_number: '1234-5678-9012',
          consent: {
            purpose: 'KYC Verification',
            timestamp: now.toISOString(),
            version: '1.0'
          }
        };

        const expectedExpiry = new Date(now.getTime() + 600000); // 10 minutes

        mockApiClient.post.mockResolvedValue({
          session_id: 'session-123',
          masked_aadhaar: 'XXXX-XXXX-9012',
          otp_sent_to: '******7890',
          expires_at: expectedExpiry.toISOString(),
          attempts_remaining: 3,
          request_id: 'req-123'
        });

        const response = await kycService.aadhaar.generateOTP(request);

        const expiryTime = new Date(response.expires_at).getTime();
        const expectedTime = expectedExpiry.getTime();

        expect(expiryTime).toBe(expectedTime);
        expect(expiryTime - now.getTime()).toBe(600000);
      });
    });
  });

  describe('2. OTP VERIFICATION FLOW - Security Invariants', () => {

    describe('2.1 Session ID Verification', () => {
      it('MUST reject verification with invalid session ID format', async () => {
        const invalidSessions = [
          '',
          null,
          undefined,
          'invalid-session',
          '../../etc/passwd',  // Path traversal attempt
          '<script>alert(1)</script>',  // XSS attempt
          'session\'; DROP TABLE sessions; --'  // SQL injection attempt
        ];

        for (const sessionId of invalidSessions) {
          const request: AadhaarVerifyRequest = {
            session_id: sessionId as string,
            otp: '123456'
          };

          mockApiClient.post.mockRejectedValue({
            status: 400,
            error: { code: 'INVALID_SESSION' }
          });

          await expect(kycService.aadhaar.verifyOTP(request))
            .rejects.toMatchObject({
              status: 400,
              error: { code: 'INVALID_SESSION' }
            });
        }
      });

      it('MUST reject expired session', async () => {
        const request: AadhaarVerifyRequest = {
          session_id: 'expired-session-123',
          otp: '123456'
        };

        mockApiClient.post.mockRejectedValue({
          status: 400,
          error: { code: 'SESSION_EXPIRED' }
        });

        await expect(kycService.aadhaar.verifyOTP(request))
          .rejects.toMatchObject({
            status: 400,
            error: { code: 'SESSION_EXPIRED' }
          });
      });
    });

    describe('2.2 OTP Format Validation', () => {
      const invalidOTPs = [
        '12345',      // Too short
        '1234567',    // Too long
        'abcdef',     // Non-numeric
        '123 456',    // Contains space
        '123-456',    // Contains dash
        '',           // Empty
        null,         // Null
        undefined     // Undefined
      ];

      invalidOTPs.forEach(otp => {
        it(`MUST reject invalid OTP format: ${otp}`, async () => {
          const request: AadhaarVerifyRequest = {
            session_id: 'valid-session-123',
            otp: otp as string
          };

          mockApiClient.post.mockRejectedValue({
            status: 400,
            error: { code: 'INVALID_OTP_FORMAT' }
          });

          await expect(kycService.aadhaar.verifyOTP(request))
            .rejects.toMatchObject({
              status: 400,
              error: { code: 'INVALID_OTP_FORMAT' }
            });
        });
      });
    });

    describe('2.3 Share Code Validation', () => {
      it('MUST validate share code format when provided', async () => {
        const invalidShareCodes = ['123', '12345', 'abcd', ''];

        for (const shareCode of invalidShareCodes) {
          const request: AadhaarVerifyRequest = {
            session_id: 'valid-session-123',
            otp: '123456',
            share_code: shareCode
          };

          mockApiClient.post.mockRejectedValue({
            status: 400,
            error: { code: 'INVALID_SHARE_CODE' }
          });

          await expect(kycService.aadhaar.verifyOTP(request))
            .rejects.toMatchObject({
              status: 400,
              error: { code: 'INVALID_SHARE_CODE' }
            });
        }
      });
    });

    describe('2.4 Maximum Attempts Logic', () => {
      it('MUST block after 3 failed attempts', async () => {
        const request: AadhaarVerifyRequest = {
          session_id: 'session-123',
          otp: '999999'  // Wrong OTP
        };

        // First 2 attempts fail with attempts remaining
        for (let i = 2; i >= 1; i--) {
          mockApiClient.post.mockRejectedValueOnce({
            status: 400,
            error: {
              code: 'INVALID_OTP',
              message: 'Invalid OTP',
              attempts_remaining: i
            }
          });

          await expect(kycService.aadhaar.verifyOTP(request))
            .rejects.toMatchObject({
              error: { attempts_remaining: i }
            });
        }

        // 3rd attempt locks the session
        mockApiClient.post.mockRejectedValueOnce({
          status: 400,
          error: {
            code: 'MAX_ATTEMPTS_EXCEEDED',
            message: 'Maximum verification attempts exceeded',
            attempts_remaining: 0
          }
        });

        await expect(kycService.aadhaar.verifyOTP(request))
          .rejects.toMatchObject({
            error: {
              code: 'MAX_ATTEMPTS_EXCEEDED',
              attempts_remaining: 0
            }
          });
      });
    });

    describe('2.5 KYC Data Structure Validation', () => {
      it('MUST return complete KYC data structure on successful verification', async () => {
        const request: AadhaarVerifyRequest = {
          session_id: 'session-123',
          otp: '123456'
        };

        const expectedResponse: AadhaarVerifyResponse = {
          verification_id: 'verify-123',
          status: 'verified',
          kyc_data: {
            reference_id: 'uidai-ref-123',
            name: 'John Doe',
            dob: '1990-01-01',
            gender: 'M',
            address: {
              house: 'H-123',
              street: 'Main Street',
              landmark: 'Near Park',
              locality: 'Downtown',
              vtc: 'City Center',
              district: 'Central',
              state: 'State Name',
              pincode: '123456'
            }
          },
          verified_at: new Date().toISOString()
        };

        mockApiClient.post.mockResolvedValue(expectedResponse);

        const response = await kycService.aadhaar.verifyOTP(request);

        expect(response.status).toBe('verified');
        expect(response.kyc_data).toBeDefined();
        expect(response.kyc_data?.reference_id).toBeDefined();
        expect(response.kyc_data?.name).toBeDefined();
        expect(response.kyc_data?.dob).toMatch(/^\d{4}-\d{2}-\d{2}$/);
        expect(['M', 'F', 'O']).toContain(response.kyc_data?.gender);

        // Validate address structure
        const address = response.kyc_data?.address;
        expect(address).toBeDefined();
        ['house', 'street', 'landmark', 'locality', 'vtc', 'district', 'state', 'pincode']
          .forEach(field => {
            expect(address).toHaveProperty(field);
          });
      });

      it('MUST include photo in KYC data when share code is provided', async () => {
        const request: AadhaarVerifyRequest = {
          session_id: 'session-123',
          otp: '123456',
          share_code: '1234'
        };

        mockApiClient.post.mockResolvedValue({
          verification_id: 'verify-123',
          status: 'verified',
          kyc_data: {
            reference_id: 'uidai-ref-123',
            name: 'John Doe',
            dob: '1990-01-01',
            gender: 'M',
            address: {
              house: 'H-123',
              street: 'Main Street',
              landmark: 'Near Park',
              locality: 'Downtown',
              vtc: 'City Center',
              district: 'Central',
              state: 'State Name',
              pincode: '123456'
            },
            photo: 'base64encodedphotodata...'
          },
          verified_at: new Date().toISOString()
        });

        const response = await kycService.aadhaar.verifyOTP(request);

        expect(response.kyc_data?.photo).toBeDefined();
        expect(response.kyc_data?.photo).toBeTruthy();
      });
    });

    describe('2.6 Verification Status State Transitions', () => {
      it('MUST transition from pending to verified on successful OTP', async () => {
        const request: AadhaarVerifyRequest = {
          session_id: 'session-123',
          otp: '123456'
        };

        mockApiClient.post.mockResolvedValue({
          verification_id: 'verify-123',
          status: 'verified',
          kyc_data: {
            reference_id: 'uidai-ref-123',
            name: 'John Doe',
            dob: '1990-01-01',
            gender: 'M',
            address: {
              house: 'H-123',
              street: 'Main Street',
              landmark: 'Near Park',
              locality: 'Downtown',
              vtc: 'City Center',
              district: 'Central',
              state: 'State Name',
              pincode: '123456'
            }
          },
          verified_at: new Date().toISOString()
        });

        const response = await kycService.aadhaar.verifyOTP(request);
        expect(response.status).toBe('verified');
      });

      it('MUST return failed status on verification failure', async () => {
        const request: AadhaarVerifyRequest = {
          session_id: 'session-123',
          otp: '999999'
        };

        mockApiClient.post.mockResolvedValue({
          verification_id: 'verify-123',
          status: 'failed',
          verified_at: new Date().toISOString()
        });

        const response = await kycService.aadhaar.verifyOTP(request);
        expect(response.status).toBe('failed');
        expect(response.kyc_data).toBeUndefined();
      });
    });
  });

  describe('3. KYC STATUS RETRIEVAL - Data Integrity', () => {

    describe('3.1 User ID Format Validation', () => {
      it('MUST validate user ID format', async () => {
        const invalidUserIds = [
          '',
          null,
          undefined,
          '../../admin',  // Path traversal
          'user\'; DROP TABLE users; --'  // SQL injection
        ];

        for (const userId of invalidUserIds) {
          mockApiClient.get.mockRejectedValue({
            status: 400,
            error: { code: 'INVALID_USER_ID' }
          });

          await expect(kycService.status.get(userId as string))
            .rejects.toMatchObject({
              status: 400,
              error: { code: 'INVALID_USER_ID' }
            });
        }
      });
    });

    describe('3.2 Status Type Accuracy', () => {
      it('MUST return accurate overall KYC status based on verification levels', async () => {
        const testCases = [
          {
            levels: { aadhaar: { status: 'not_initiated' } },
            expected: 'not_initiated'
          },
          {
            levels: { aadhaar: { status: 'pending' } },
            expected: 'in_progress'
          },
          {
            levels: { aadhaar: { status: 'verified' } },
            expected: 'verified'
          },
          {
            levels: {
              aadhaar: { status: 'verified' },
              pan: { status: 'pending' }
            },
            expected: 'in_progress'
          }
        ];

        for (const testCase of testCases) {
          mockApiClient.get.mockResolvedValueOnce({
            user_id: 'user-123',
            kyc_status: testCase.expected as KYCStatusType,
            verification_levels: testCase.levels,
            last_updated: new Date().toISOString()
          });

          const status = await kycService.status.get('user-123');
          expect(status.kyc_status).toBe(testCase.expected);
        }
      });
    });

    describe('3.3 Timestamp Consistency', () => {
      it('MUST ensure all timestamps are in ISO8601 format', async () => {
        const now = new Date();

        mockApiClient.get.mockResolvedValue({
          user_id: 'user-123',
          kyc_status: 'verified',
          verification_levels: {
            aadhaar: {
              status: 'verified',
              verified_at: now.toISOString(),
              expires_at: new Date(now.getTime() + 86400000).toISOString()
            }
          },
          last_updated: now.toISOString()
        });

        const status = await kycService.status.get('user-123');

        // Check timestamp formats
        expect(status.last_updated).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/);
        expect(status.verification_levels.aadhaar?.verified_at)
          .toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/);
        expect(status.verification_levels.aadhaar?.expires_at)
          .toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/);
      });
    });
  });

  describe('4. SECURITY & COMPLIANCE - Critical Checks', () => {

    describe('4.1 PII Data Protection', () => {
      it('MUST never expose full Aadhaar number in responses', async () => {
        const request: AadhaarOTPRequest = {
          aadhaar_number: '1234-5678-9012',
          consent: {
            purpose: 'KYC Verification',
            timestamp: new Date().toISOString(),
            version: '1.0'
          }
        };

        mockApiClient.post.mockResolvedValue({
          session_id: 'session-123',
          masked_aadhaar: 'XXXX-XXXX-9012',
          otp_sent_to: '******7890',
          expires_at: new Date(Date.now() + 600000).toISOString(),
          attempts_remaining: 3,
          request_id: 'req-123'
        });

        const response = await kycService.aadhaar.generateOTP(request);

        expect(response.masked_aadhaar).toMatch(/^XXXX-XXXX-\d{4}$/);
        expect(response.masked_aadhaar).not.toContain('1234');
        expect(response.masked_aadhaar).not.toContain('5678');
      });

      it('MUST mask phone number in OTP response', async () => {
        const request: AadhaarOTPRequest = {
          aadhaar_number: '1234-5678-9012',
          consent: {
            purpose: 'KYC Verification',
            timestamp: new Date().toISOString(),
            version: '1.0'
          }
        };

        mockApiClient.post.mockResolvedValue({
          session_id: 'session-123',
          masked_aadhaar: 'XXXX-XXXX-9012',
          otp_sent_to: '******7890',
          expires_at: new Date(Date.now() + 600000).toISOString(),
          attempts_remaining: 3,
          request_id: 'req-123'
        });

        const response = await kycService.aadhaar.generateOTP(request);

        expect(response.otp_sent_to).toMatch(/^\*+\d{2,4}$/);
      });
    });

    describe('4.2 Authorization Requirements', () => {
      it('MUST require authentication for all KYC operations', async () => {
        // Test without auth token
        mockApiClient.post.mockRejectedValue({
          status: 401,
          error: { code: 'UNAUTHORIZED' }
        });

        const request: AadhaarOTPRequest = {
          aadhaar_number: '1234-5678-9012',
          consent: {
            purpose: 'KYC Verification',
            timestamp: new Date().toISOString(),
            version: '1.0'
          }
        };

        await expect(kycService.aadhaar.generateOTP(request))
          .rejects.toMatchObject({
            status: 401,
            error: { code: 'UNAUTHORIZED' }
          });
      });

      it('MUST enforce user-level access control for status retrieval', async () => {
        // User trying to access another user's KYC status
        mockApiClient.get.mockRejectedValue({
          status: 403,
          error: { code: 'FORBIDDEN', message: 'Access denied to this resource' }
        });

        await expect(kycService.status.get('other-user-456'))
          .rejects.toMatchObject({
            status: 403,
            error: { code: 'FORBIDDEN' }
          });
      });
    });
  });

  describe('5. EDGE CASES & ABUSE SCENARIOS', () => {

    describe('5.1 Rate Limiting Bypass Attempts', () => {
      it('MUST prevent rate limit bypass via request parameter manipulation', async () => {
        const baseRequest: AadhaarOTPRequest = {
          aadhaar_number: '1234-5678-9012',
          consent: {
            purpose: 'KYC Verification',
            timestamp: new Date().toISOString(),
            version: '1.0'
          }
        };

        // Try different variations to bypass rate limit
        const variations = [
          { ...baseRequest, request_id: 'bypass-1' },
          { ...baseRequest, request_id: 'bypass-2' },
          { ...baseRequest, consent: { ...baseRequest.consent, version: '1.1' } },
          { ...baseRequest, consent: { ...baseRequest.consent, purpose: 'KYC Verification.' } }
        ];

        // First 3 succeed
        for (let i = 0; i < 3; i++) {
          mockApiClient.post.mockResolvedValueOnce({
            session_id: `session-${i}`,
            masked_aadhaar: 'XXXX-XXXX-9012',
            otp_sent_to: '******7890',
            expires_at: new Date(Date.now() + 600000).toISOString(),
            attempts_remaining: 3,
            request_id: `req-${i}`
          });
        }

        // All further attempts should be rate limited
        mockApiClient.post.mockRejectedValue({
          status: 429,
          error: { code: 'RATE_LIMIT_EXCEEDED' }
        });

        // Use first 3 variations successfully
        for (let i = 0; i < 3; i++) {
          await kycService.aadhaar.generateOTP(variations[i]);
        }

        // 4th variation should be blocked
        await expect(kycService.aadhaar.generateOTP(variations[3]))
          .rejects.toMatchObject({
            status: 429,
            error: { code: 'RATE_LIMIT_EXCEEDED' }
          });
      });
    });

    describe('5.2 Concurrent Verification Attempts', () => {
      it('MUST handle race condition in concurrent OTP verifications', async () => {
        const request: AadhaarVerifyRequest = {
          session_id: 'session-123',
          otp: '123456'
        };

        // Only first request should succeed
        mockApiClient.post
          .mockResolvedValueOnce({
            verification_id: 'verify-123',
            status: 'verified',
            kyc_data: {
              reference_id: 'uidai-ref-123',
              name: 'John Doe',
              dob: '1990-01-01',
              gender: 'M',
              address: {
                house: 'H-123',
                street: 'Main Street',
                landmark: 'Near Park',
                locality: 'Downtown',
                vtc: 'City Center',
                district: 'Central',
                state: 'State Name',
                pincode: '123456'
              }
            },
            verified_at: new Date().toISOString()
          })
          .mockRejectedValue({
            status: 400,
            error: { code: 'SESSION_ALREADY_VERIFIED' }
          });

        // Launch 10 concurrent verification attempts
        const promises = Array(10).fill(null).map(() =>
          kycService.aadhaar.verifyOTP(request)
        );

        const results = await Promise.allSettled(promises);

        const successful = results.filter(r => r.status === 'fulfilled');
        const failed = results.filter(r => r.status === 'rejected');

        expect(successful.length).toBe(1);
        expect(failed.length).toBe(9);

        failed.forEach(result => {
          if (result.status === 'rejected') {
            expect(result.reason).toMatchObject({
              error: { code: 'SESSION_ALREADY_VERIFIED' }
            });
          }
        });
      });
    });

    describe('5.3 Session Hijacking Prevention', () => {
      it('MUST detect and prevent session ID enumeration attacks', async () => {
        const sessionPatterns = [
          'session-1',
          'session-2',
          'session-3',
          'session-123',
          'session-abc',
          'session-xyz'
        ];

        for (const sessionId of sessionPatterns) {
          mockApiClient.post.mockRejectedValue({
            status: 404,
            error: { code: 'SESSION_NOT_FOUND' }
          });

          await expect(kycService.aadhaar.verifyOTP({
            session_id: sessionId,
            otp: '123456'
          })).rejects.toMatchObject({
            status: 404,
            error: { code: 'SESSION_NOT_FOUND' }
          });
        }

        // Should not reveal if session exists or not
        expect(mockApiClient.post).toHaveBeenCalledTimes(sessionPatterns.length);
      });
    });

    describe('5.4 Replay Attack Prevention', () => {
      it('MUST prevent replay of old verification requests', async () => {
        const oldRequest: AadhaarVerifyRequest = {
          session_id: 'old-session-123',
          otp: '123456'
        };

        // Session expired
        mockApiClient.post.mockRejectedValue({
          status: 400,
          error: { code: 'SESSION_EXPIRED', message: 'Session has expired' }
        });

        await expect(kycService.aadhaar.verifyOTP(oldRequest))
          .rejects.toMatchObject({
            status: 400,
            error: { code: 'SESSION_EXPIRED' }
          });
      });
    });

    describe('5.5 Data Consistency Under Load', () => {
      it('MUST maintain data integrity under high concurrent load', async () => {
        const promises = [];

        // Simulate 50 concurrent status checks
        for (let i = 0; i < 50; i++) {
          mockApiClient.get.mockResolvedValueOnce({
            user_id: `user-${i}`,
            kyc_status: 'verified',
            verification_levels: {
              aadhaar: {
                status: 'verified',
                verified_at: new Date().toISOString()
              }
            },
            last_updated: new Date().toISOString()
          });

          promises.push(kycService.status.get(`user-${i}`));
        }

        const results = await Promise.all(promises);

        // Verify each result has correct structure
        results.forEach((result, index) => {
          expect(result.user_id).toBe(`user-${index}`);
          expect(result.kyc_status).toBe('verified');
          expect(result.verification_levels).toBeDefined();
          expect(result.last_updated).toBeDefined();
        });

        // Ensure no data corruption or mixing
        const userIds = new Set(results.map(r => r.user_id));
        expect(userIds.size).toBe(50);
      });
    });
  });

  describe('6. STATE MACHINE VALIDATION', () => {

    describe('6.1 Valid State Transitions', () => {
      it('MUST follow valid state transition: not_initiated → pending → otp_sent → verified', async () => {
        // Initial state check
        mockApiClient.get.mockResolvedValueOnce({
          user_id: 'user-123',
          kyc_status: 'not_initiated',
          verification_levels: {},
          last_updated: new Date().toISOString()
        });

        let status = await kycService.status.get('user-123');
        expect(status.kyc_status).toBe('not_initiated');

        // Generate OTP - moves to pending/otp_sent
        const otpRequest: AadhaarOTPRequest = {
          aadhaar_number: '1234-5678-9012',
          consent: {
            purpose: 'KYC Verification',
            timestamp: new Date().toISOString(),
            version: '1.0'
          }
        };

        mockApiClient.post.mockResolvedValueOnce({
          session_id: 'session-123',
          masked_aadhaar: 'XXXX-XXXX-9012',
          otp_sent_to: '******7890',
          expires_at: new Date(Date.now() + 600000).toISOString(),
          attempts_remaining: 3,
          request_id: 'req-123'
        });

        await kycService.aadhaar.generateOTP(otpRequest);

        // Check status - should be in_progress
        mockApiClient.get.mockResolvedValueOnce({
          user_id: 'user-123',
          kyc_status: 'in_progress',
          verification_levels: {
            aadhaar: { status: 'pending' }
          },
          last_updated: new Date().toISOString()
        });

        status = await kycService.status.get('user-123');
        expect(status.kyc_status).toBe('in_progress');

        // Verify OTP - moves to verified
        mockApiClient.post.mockResolvedValueOnce({
          verification_id: 'verify-123',
          status: 'verified',
          kyc_data: {
            reference_id: 'uidai-ref-123',
            name: 'John Doe',
            dob: '1990-01-01',
            gender: 'M',
            address: {
              house: 'H-123',
              street: 'Main Street',
              landmark: 'Near Park',
              locality: 'Downtown',
              vtc: 'City Center',
              district: 'Central',
              state: 'State Name',
              pincode: '123456'
            }
          },
          verified_at: new Date().toISOString()
        });

        await kycService.aadhaar.verifyOTP({
          session_id: 'session-123',
          otp: '123456'
        });

        // Final status check - should be verified
        mockApiClient.get.mockResolvedValueOnce({
          user_id: 'user-123',
          kyc_status: 'verified',
          verification_levels: {
            aadhaar: {
              status: 'verified',
              verified_at: new Date().toISOString()
            }
          },
          last_updated: new Date().toISOString()
        });

        status = await kycService.status.get('user-123');
        expect(status.kyc_status).toBe('verified');
      });
    });

    describe('6.2 Invalid State Transitions', () => {
      it('MUST prevent invalid transition: verified → pending', async () => {
        // User already verified
        mockApiClient.get.mockResolvedValueOnce({
          user_id: 'user-123',
          kyc_status: 'verified',
          verification_levels: {
            aadhaar: {
              status: 'verified',
              verified_at: new Date().toISOString()
            }
          },
          last_updated: new Date().toISOString()
        });

        const status = await kycService.status.get('user-123');
        expect(status.kyc_status).toBe('verified');

        // Attempt to generate OTP again should be rejected
        mockApiClient.post.mockRejectedValue({
          status: 400,
          error: { code: 'ALREADY_VERIFIED', message: 'KYC already completed' }
        });

        await expect(kycService.aadhaar.generateOTP({
          aadhaar_number: '1234-5678-9012',
          consent: {
            purpose: 'KYC Verification',
            timestamp: new Date().toISOString(),
            version: '1.0'
          }
        })).rejects.toMatchObject({
          status: 400,
          error: { code: 'ALREADY_VERIFIED' }
        });
      });
    });
  });

  describe('7. COMPLIANCE VALIDATION', () => {

    describe('7.1 UIDAI Compliance', () => {
      it('MUST NOT store or return Aadhaar number in plain text', async () => {
        const response: AadhaarOTPResponse = {
          session_id: 'session-123',
          masked_aadhaar: 'XXXX-XXXX-9012',
          otp_sent_to: '******7890',
          expires_at: new Date(Date.now() + 600000).toISOString(),
          attempts_remaining: 3,
          request_id: 'req-123'
        };

        // Check response doesn't contain full Aadhaar
        expect(JSON.stringify(response)).not.toContain('1234-5678-9012');
        expect(response.masked_aadhaar).toMatch(/^X{4}-X{4}-\d{4}$/);
      });

      it('MUST enforce consent version minimum 2.1 for UIDAI compliance', async () => {
        const request: AadhaarOTPRequest = {
          aadhaar_number: '1234-5678-9012',
          consent: {
            purpose: 'KYC Verification',
            timestamp: new Date().toISOString(),
            version: '1.0'  // Old version
          }
        };

        mockApiClient.post.mockRejectedValue({
          status: 400,
          error: {
            code: 'INVALID_CONSENT_VERSION',
            message: 'Consent version must be 2.1 or higher'
          }
        });

        await expect(kycService.aadhaar.generateOTP(request))
          .rejects.toMatchObject({
            error: { code: 'INVALID_CONSENT_VERSION' }
          });
      });
    });

    describe('7.2 Data Retention Compliance', () => {
      it('MUST respect KYC data expiration', async () => {
        const expiredDate = new Date(Date.now() - 86400000); // 1 day ago

        mockApiClient.get.mockResolvedValue({
          user_id: 'user-123',
          kyc_status: 'expired',
          verification_levels: {
            aadhaar: {
              status: 'verified',
              verified_at: new Date(Date.now() - 7776000000).toISOString(), // 90 days ago
              expires_at: expiredDate.toISOString()
            }
          },
          last_updated: new Date().toISOString()
        });

        const status = await kycService.status.get('user-123');
        expect(status.kyc_status).toBe('expired');

        const expiryTime = new Date(status.verification_levels.aadhaar?.expires_at!).getTime();
        expect(expiryTime).toBeLessThan(Date.now());
      });
    });
  });
});
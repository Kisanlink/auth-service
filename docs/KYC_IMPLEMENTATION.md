# KYC/Aadhaar Validation API Implementation

## Overview

This document describes the implementation of KYC/Aadhaar validation APIs for the auth-service library. The implementation follows functional programming principles, maintains zero storage dependencies at the library level, and provides a clean, type-safe interface for KYC operations.

## Implementation Summary

### Files Modified/Created

1. **types/index.ts** - Added comprehensive KYC type definitions
2. **services/kycService.ts** - Implemented KYC service factory following functional programming pattern
3. **index.ts** - Updated to export KYC service and integrate with main AAAService factory

### Architecture

The KYC service follows the existing auth-service patterns:
- **Functional Programming**: Pure functions with no side effects
- **Dependency Injection**: API client injected via factory pattern
- **Type Safety**: Full TypeScript type definitions
- **Zero Storage**: No direct database/storage dependencies (library-level only)

## API Endpoints

### 1. Generate OTP for Aadhaar Verification

```typescript
POST /api/v1/kyc/aadhaar/otp

Request:
{
  aadhaar_number: string;        // Format: "1234-5678-9012"
  consent: {
    purpose: string;              // e.g., "KYC Verification"
    timestamp: string;            // ISO8601 format
    version: string;              // Consent version e.g., "1.0"
  };
  request_id?: string;            // Optional idempotency key
}

Response:
{
  session_id: string;             // Session UUID for verification
  masked_aadhaar: string;         // "XXXX-XXXX-1234"
  otp_sent_to: string;            // "******7890"
  expires_at: string;             // ISO8601 timestamp
  attempts_remaining: number;     // 3
  request_id: string;             // Idempotency key
}
```

### 2. Verify Aadhaar OTP

```typescript
POST /api/v1/kyc/aadhaar/otp/verify

Request:
{
  session_id: string;             // From generateOTP response
  otp: string;                    // 6-digit OTP
  share_code?: string;            // Optional 4-digit for eKYC with photo
}

Response:
{
  verification_id: string;        // Unique verification ID
  status: 'verified' | 'failed';
  kyc_data?: {                    // Only if verified
    reference_id: string;         // UIDAI reference
    name: string;
    dob: string;                  // "YYYY-MM-DD"
    gender: 'M' | 'F' | 'O';
    address: {
      house: string;
      street: string;
      landmark: string;
      locality: string;
      vtc: string;
      district: string;
      state: string;
      pincode: string;
    };
    photo?: string;               // Base64 encoded if share_code provided
  };
  verified_at: string;            // ISO8601 timestamp
}
```

### 3. Get KYC Status

```typescript
GET /api/v1/kyc/status/{user_id}

Response:
{
  user_id: string;
  kyc_status: 'not_initiated' | 'in_progress' | 'verified' | 'failed' | 'expired';
  verification_levels: {
    aadhaar?: {
      status: 'verified' | 'pending' | 'not_initiated';
      verified_at?: string;       // ISO8601
      expires_at?: string;        // ISO8601
    };
    pan?: {
      status: 'verified' | 'pending' | 'not_initiated';
      verified_at?: string;
    };
    bank_account?: {
      status: 'verified' | 'pending' | 'not_initiated';
      verified_at?: string;
    };
  };
  next_action?: string;           // Guidance for next step
  last_updated: string;           // ISO8601 timestamp
}
```

## Usage Examples

### Basic Setup

```typescript
import createAAAService from 'auth-service';

const aaaService = createAAAService({
  baseURL: 'https://api.example.com',
  getAccessToken: () => localStorage.getItem('access_token'),
});

const kycService = aaaService.kyc;
```

### Example 1: Complete Aadhaar Verification Flow

```typescript
async function verifyAadhaar(aadhaarNumber: string, otp: string) {
  try {
    // Step 1: Generate OTP
    const otpResponse = await kycService.aadhaar.generateOTP({
      aadhaar_number: aadhaarNumber,
      consent: {
        purpose: 'KYC Verification for Account Opening',
        timestamp: new Date().toISOString(),
        version: '1.0',
      },
    });

    console.log('OTP sent to:', otpResponse.otp_sent_to);
    console.log('Session expires at:', otpResponse.expires_at);
    console.log('Attempts remaining:', otpResponse.attempts_remaining);

    // Step 2: Verify OTP (after user enters OTP)
    const verifyResponse = await kycService.aadhaar.verifyOTP({
      session_id: otpResponse.session_id,
      otp: otp,
      share_code: '1234', // Optional: for photo
    });

    if (verifyResponse.status === 'verified') {
      console.log('KYC Verified!');
      console.log('Name:', verifyResponse.kyc_data?.name);
      console.log('DOB:', verifyResponse.kyc_data?.dob);
      console.log('Address:', verifyResponse.kyc_data?.address);
      return verifyResponse.kyc_data;
    } else {
      console.error('Verification failed');
      return null;
    }
  } catch (error: any) {
    console.error('KYC Error:', error.message);
    throw error;
  }
}
```

### Example 2: Check KYC Status

```typescript
async function checkUserKYCStatus(userId: string) {
  try {
    const status = await kycService.status.get(userId);

    console.log('Overall KYC Status:', status.kyc_status);

    if (status.verification_levels.aadhaar) {
      console.log('Aadhaar Status:', status.verification_levels.aadhaar.status);
      console.log('Verified At:', status.verification_levels.aadhaar.verified_at);
    }

    if (status.next_action) {
      console.log('Next Action:', status.next_action);
    }

    return status;
  } catch (error: any) {
    console.error('Failed to get KYC status:', error.message);
    throw error;
  }
}
```

### Example 3: Error Handling

```typescript
async function handleKYCErrors() {
  try {
    await kycService.aadhaar.generateOTP({
      aadhaar_number: 'invalid',
      consent: {
        purpose: 'KYC Verification',
        timestamp: new Date().toISOString(),
        version: '1.0',
      },
    });
  } catch (error: any) {
    // Parse error response
    if (error.status === 400) {
      console.error('Invalid Aadhaar number format');
    } else if (error.status === 429) {
      console.error('Rate limit exceeded - too many requests');
      // error.response may contain retry_after
    } else if (error.status === 503) {
      console.error('KYC service temporarily unavailable');
    } else {
      console.error('Unexpected error:', error.message);
    }
  }
}
```

### Example 4: React Hook Integration

```typescript
import { useState } from 'react';
import { aaaService } from './services/auth';

function useAadhaarVerification() {
  const [loading, setLoading] = useState(false);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const generateOTP = async (aadhaarNumber: string) => {
    try {
      setLoading(true);
      setError(null);

      const response = await aaaService.kyc.aadhaar.generateOTP({
        aadhaar_number: aadhaarNumber,
        consent: {
          purpose: 'KYC Verification',
          timestamp: new Date().toISOString(),
          version: '1.0',
        },
      });

      setSessionId(response.session_id);
      return response;
    } catch (err: any) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const verifyOTP = async (otp: string) => {
    if (!sessionId) {
      throw new Error('No active session');
    }

    try {
      setLoading(true);
      setError(null);

      const response = await aaaService.kyc.aadhaar.verifyOTP({
        session_id: sessionId,
        otp: otp,
      });

      return response;
    } catch (err: any) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  return { generateOTP, verifyOTP, loading, error };
}
```

## Type Definitions

All KYC types are exported from the main package:

```typescript
import type {
  // Request Types
  AadhaarOTPRequest,
  AadhaarVerifyRequest,
  KYCConsent,

  // Response Types
  AadhaarOTPResponse,
  AadhaarVerifyResponse,
  KYCStatus,
  KYCData,

  // Supporting Types
  AadhaarAddress,
  VerificationLevel,
  VerificationLevels,
  KYCStatusType,
  KYCErrorResponse,
} from 'auth-service';
```

## Security Considerations

### 1. PII Data Handling

**CRITICAL**: KYC data contains sensitive Personally Identifiable Information (PII):
- Never log Aadhaar numbers, OTPs, or KYC data in plain text
- Encrypt KYC data at rest if storing
- Implement proper access controls
- Follow UIDAI guidelines and data protection regulations

### 2. Consent Management

- Always obtain explicit user consent before KYC verification
- Store consent records with purpose, timestamp, and version
- Allow users to revoke consent
- Comply with GDPR/DPDP Act requirements

### 3. Rate Limiting

The API implements rate limiting to prevent abuse:
- OTP generation: 3 requests per hour per user
- OTP verification: 5 attempts per 15 minutes
- Status checks: 10 requests per minute

### 4. Session Security

- OTP sessions expire in 10 minutes (600 seconds)
- Maximum 3 verification attempts per session
- Sessions are single-use - new OTP required after expiry

### 5. Transport Security

- Always use HTTPS/TLS 1.3
- Implement proper authentication (Bearer token)
- Validate SSL certificates

## Error Handling

### Common Error Codes

| Status | Code | Description | Action |
|--------|------|-------------|--------|
| 400 | INVALID_AADHAAR | Invalid Aadhaar number format | Validate format (12 digits) |
| 400 | INVALID_OTP | OTP incorrect or expired | Retry or generate new OTP |
| 400 | SESSION_EXPIRED | Session expired | Generate new OTP |
| 400 | CONSENT_REQUIRED | Missing/invalid consent | Provide valid consent |
| 429 | RATE_LIMIT_EXCEEDED | Too many requests | Wait for retry_after seconds |
| 503 | SERVICE_UNAVAILABLE | External service down | Retry later with backoff |

### Error Response Structure

```typescript
interface KYCErrorResponse {
  error: {
    code: string;
    message: string;
    details?: unknown;
    retry_after?: number;        // Seconds to wait (429 errors)
    attempts_remaining?: number;  // For OTP verification
  };
}
```

## Testing

### Unit Test Example

```typescript
import { describe, it, expect, vi } from 'vitest';
import createKYCService from './services/kycService';

describe('KYC Service', () => {
  it('should generate OTP successfully', async () => {
    const mockApiClient = {
      post: vi.fn().mockResolvedValue({
        session_id: 'test-session-123',
        masked_aadhaar: 'XXXX-XXXX-9012',
        otp_sent_to: '******7890',
        expires_at: new Date(Date.now() + 600000).toISOString(),
        attempts_remaining: 3,
        request_id: 'req-123',
      }),
      get: vi.fn(),
      put: vi.fn(),
      delete: vi.fn(),
    };

    const kycService = createKYCService(mockApiClient);

    const result = await kycService.aadhaar.generateOTP({
      aadhaar_number: '1234-5678-9012',
      consent: {
        purpose: 'KYC Verification',
        timestamp: new Date().toISOString(),
        version: '1.0',
      },
    });

    expect(result.session_id).toBe('test-session-123');
    expect(result.masked_aadhaar).toBe('XXXX-XXXX-9012');
  });
});
```

## Performance Considerations

1. **Caching**: KYC status can be cached for 5-10 minutes to reduce API calls
2. **Timeouts**: Implement 30-second timeout for OTP operations
3. **Retry Logic**: Use exponential backoff for 503 errors
4. **Circuit Breaker**: Implement circuit breaker for external service failures

## Compliance

This implementation is designed to comply with:
- UIDAI Aadhaar Authentication guidelines
- GDPR (General Data Protection Regulation)
- DPDP Act (Digital Personal Data Protection Act)
- ISO 27001 security standards

## Next Steps

For production deployment, implement:
1. Server-side validation and gateway integration
2. Database schema for KYC sessions and verifications
3. Audit logging for compliance
4. Encryption services for PII data
5. Rate limiting middleware
6. Monitoring and alerting

## References

- [KYC Architecture Design](.kiro/specs/kyc-aadhaar-architecture.md)
- [KYC Project Structure](.kiro/specs/kyc-project-structure.md)
- [UIDAI Authentication API](https://uidai.gov.in/ecosystem/authentication-devices-documents/about-aadhaar-paperless-offline-e-kyc.html)

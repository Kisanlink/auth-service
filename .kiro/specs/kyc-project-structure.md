# KYC Module Project Structure

## Recommended Directory Structure

```
auth-service/
├── services/
│   ├── kycService.ts                 # Main KYC service factory
│   ├── kycOrchestrationService.ts    # Workflow orchestration
│   └── kycAuditService.ts            # Audit logging service
│
├── integrations/
│   ├── aadhaarGateway.ts             # UIDAI API integration
│   ├── digilockerGateway.ts          # DigiLocker integration (future)
│   └── kycProviders/
│       ├── provider.interface.ts      # Common provider interface
│       └── uidaiProvider.ts          # UIDAI-specific implementation
│
├── types/
│   ├── kyc.ts                         # KYC type definitions
│   ├── aadhaar.ts                     # Aadhaar-specific types
│   └── audit.ts                       # Audit log types
│
├── security/
│   ├── kycEncryption.ts              # KYC-specific encryption
│   ├── tokenization.ts                # Aadhaar tokenization
│   └── dataProtection.ts             # GDPR/DPDP compliance
│
├── stateMachines/
│   ├── kycStateMachine.ts            # KYC workflow state machine
│   └── states/
│       ├── consentState.ts           # Consent handling
│       ├── otpState.ts               # OTP generation/verification
│       └── verificationState.ts      # Final verification
│
├── middleware/
│   ├── kycRateLimiter.ts             # KYC-specific rate limiting
│   ├── kycValidator.ts               # Request validation
│   └── kycErrorHandler.ts            # Error handling
│
├── cache/
│   ├── kycCacheStrategy.ts           # Caching implementation
│   └── cacheProviders/
│       ├── inMemory.ts               # L1 cache
│       └── redis.ts                  # L2 cache
│
├── utils/
│   ├── aadhaarValidator.ts           # Aadhaar number validation
│   ├── kycHelpers.ts                 # Utility functions
│   └── circuitBreaker.ts             # Circuit breaker implementation
│
├── errors/
│   ├── kycErrors.ts                  # KYC error definitions
│   └── errorCodes.ts                 # Error code constants
│
├── monitoring/
│   ├── kycMetrics.ts                 # Prometheus metrics
│   ├── kycTracing.ts                 # OpenTelemetry tracing
│   └── alerts.yaml                   # Alert configurations
│
├── database/
│   ├── migrations/
│   │   ├── 001_create_kyc_tables.sql
│   │   ├── 002_add_audit_tables.sql
│   │   └── 003_add_indexes.sql
│   └── repositories/
│       ├── kycRepository.ts          # KYC data access
│       └── auditRepository.ts        # Audit log access
│
├── tests/
│   ├── unit/
│   │   ├── services/
│   │   │   ├── kycService.test.ts
│   │   │   └── kycOrchestration.test.ts
│   │   ├── security/
│   │   │   ├── encryption.test.ts
│   │   │   └── tokenization.test.ts
│   │   └── utils/
│   │       └── aadhaarValidator.test.ts
│   ├── integration/
│   │   ├── kyc/
│   │   │   ├── otpGeneration.test.ts
│   │   │   ├── otpVerification.test.ts
│   │   │   └── statusCheck.test.ts
│   │   └── gateways/
│   │       └── aadhaarGateway.test.ts
│   ├── e2e/
│   │   └── kycFlow.test.ts
│   └── fixtures/
│       ├── kycResponses.json
│       └── testData.ts
│
├── docs/
│   ├── api/
│   │   ├── kyc-api.yaml              # OpenAPI specification
│   │   └── postman/
│   │       └── kyc-collection.json
│   ├── security/
│   │   ├── threat-model.md
│   │   └── security-checklist.md
│   └── compliance/
│       ├── uidai-compliance.md
│       └── gdpr-dpdp-compliance.md
│
└── config/
    ├── kyc.config.ts                  # KYC configuration
    └── environments/
        ├── development.ts
        ├── staging.ts
        └── production.ts
```

## File Templates

### 1. Main KYC Service (`services/kycService.ts`)

```typescript
import { ApiClient } from '../utils/apiClient';
import { KYCOrchestrationService } from './kycOrchestrationService';
import { KYCAuditService } from './kycAuditService';
import {
  AadhaarOTPRequest,
  AadhaarOTPResponse,
  AadhaarVerifyRequest,
  AadhaarVerifyResponse,
  KYCStatus
} from '../types/kyc';

export interface KYCServiceConfig {
  orchestration: KYCOrchestrationService;
  audit: KYCAuditService;
}

export const createKYCService = (
  apiClient: ApiClient,
  config?: KYCServiceConfig
) => {
  const orchestration = config?.orchestration || new KYCOrchestrationService();
  const audit = config?.audit || new KYCAuditService();

  return {
    aadhaar: {
      generateOTP: async (request: AadhaarOTPRequest): Promise<AadhaarOTPResponse> => {
        // Audit the request
        await audit.logAction('AADHAAR_OTP_REQUEST', request);

        // Execute through orchestration
        const response = await orchestration.executeOTPGeneration(request);

        // Audit the response
        await audit.logAction('AADHAAR_OTP_RESPONSE', response);

        return response;
      },

      verifyOTP: async (request: AadhaarVerifyRequest): Promise<AadhaarVerifyResponse> => {
        // Audit the request
        await audit.logAction('AADHAAR_VERIFY_REQUEST', request);

        // Execute through orchestration
        const response = await orchestration.executeOTPVerification(request);

        // Audit the response
        await audit.logAction('AADHAAR_VERIFY_RESPONSE', response);

        return response;
      },
    },

    status: {
      get: async (userId: string): Promise<KYCStatus> => {
        return apiClient.get(`/api/v1/kyc/status/${userId}`);
      },
    },
  };
};
```

### 2. Aadhaar Gateway Integration (`integrations/aadhaarGateway.ts`)

```typescript
import { CircuitBreaker } from '../utils/circuitBreaker';
import { KYCEncryptionService } from '../security/kycEncryption';
import { KYCError, KYCErrorCode } from '../errors/kycErrors';

export interface AadhaarGatewayConfig {
  baseURL: string;
  apiKey: string;
  licenseKey: string;
  encryptionKey: string;
  timeout: number;
  retryConfig: {
    maxRetries: number;
    backoffMultiplier: number;
  };
}

export class AadhaarGateway {
  private circuitBreaker: CircuitBreaker;
  private encryption: KYCEncryptionService;

  constructor(private config: AadhaarGatewayConfig) {
    this.circuitBreaker = new CircuitBreaker({
      failureThreshold: 5,
      resetTimeout: 60000,
      monitoringPeriod: 120000,
    });

    this.encryption = new KYCEncryptionService(config.encryptionKey);
  }

  async generateOTP(aadhaarNumber: string): Promise<{
    sessionId: string;
    maskedNumber: string;
    otpSentTo: string;
  }> {
    return this.circuitBreaker.execute(async () => {
      try {
        // Validate Aadhaar number
        if (!this.isValidAadhaar(aadhaarNumber)) {
          throw new KYCError(
            KYCErrorCode.INVALID_AADHAAR,
            'Invalid Aadhaar number format',
            400
          );
        }

        // Encrypt Aadhaar number
        const encryptedAadhaar = await this.encryption.encryptField(
          aadhaarNumber
        );

        // Call UIDAI API
        const response = await this.callUIDAPI('/otp/generate', {
          uid: encryptedAadhaar,
          txnId: this.generateTransactionId(),
          licenseKey: this.config.licenseKey,
        });

        return {
          sessionId: response.sessionId,
          maskedNumber: this.maskAadhaar(aadhaarNumber),
          otpSentTo: response.mobile,
        };
      } catch (error) {
        this.handleGatewayError(error);
        throw error;
      }
    });
  }

  async verifyOTP(
    sessionId: string,
    otp: string
  ): Promise<{
    verified: boolean;
    kycData?: any;
  }> {
    return this.circuitBreaker.execute(async () => {
      try {
        const encryptedOTP = await this.encryption.encryptField(otp);

        const response = await this.callUIDAPI('/otp/verify', {
          sessionId,
          otp: encryptedOTP,
          txnId: this.generateTransactionId(),
        });

        if (response.status === 'SUCCESS') {
          return {
            verified: true,
            kycData: await this.decryptKYCData(response.kycData),
          };
        }

        return { verified: false };
      } catch (error) {
        this.handleGatewayError(error);
        throw error;
      }
    });
  }

  private isValidAadhaar(aadhaar: string): boolean {
    // Remove spaces and hyphens
    const cleaned = aadhaar.replace(/[\s-]/g, '');

    // Check if 12 digits
    if (!/^\d{12}$/.test(cleaned)) {
      return false;
    }

    // Verhoeff algorithm validation
    return this.verhoeffValidate(cleaned);
  }

  private verhoeffValidate(aadhaar: string): boolean {
    // Implementation of Verhoeff algorithm
    // ... (algorithm implementation)
    return true; // Placeholder
  }

  private maskAadhaar(aadhaar: string): string {
    const cleaned = aadhaar.replace(/[\s-]/g, '');
    return `XXXX-XXXX-${cleaned.slice(-4)}`;
  }

  private generateTransactionId(): string {
    return `TXN${Date.now()}${Math.random().toString(36).substr(2, 9)}`;
  }

  private async callUIDAPI(endpoint: string, data: any): Promise<any> {
    // Implementation of UIDAI API call with retries
    // ... (implementation)
    return {}; // Placeholder
  }

  private async decryptKYCData(encryptedData: any): Promise<any> {
    return this.encryption.decryptData(encryptedData);
  }

  private handleGatewayError(error: any): void {
    // Log and convert gateway errors to KYCError
    console.error('Aadhaar Gateway Error:', error);
  }
}
```

### 3. KYC State Machine (`stateMachines/kycStateMachine.ts`)

```typescript
import { EventEmitter } from 'events';
import { KYCAuditService } from '../services/kycAuditService';

export enum KYCState {
  NOT_INITIATED = 'NOT_INITIATED',
  CONSENT_PENDING = 'CONSENT_PENDING',
  OTP_GENERATION_PENDING = 'OTP_GENERATION_PENDING',
  OTP_SENT = 'OTP_SENT',
  OTP_VERIFICATION_PENDING = 'OTP_VERIFICATION_PENDING',
  VERIFIED = 'VERIFIED',
  FAILED = 'FAILED',
  EXPIRED = 'EXPIRED',
}

export enum KYCEvent {
  START = 'START',
  CONSENT_PROVIDED = 'CONSENT_PROVIDED',
  GENERATE_OTP = 'GENERATE_OTP',
  OTP_SENT_SUCCESS = 'OTP_SENT_SUCCESS',
  OTP_SENT_FAILED = 'OTP_SENT_FAILED',
  VERIFY_OTP = 'VERIFY_OTP',
  VERIFICATION_SUCCESS = 'VERIFICATION_SUCCESS',
  VERIFICATION_FAILED = 'VERIFICATION_FAILED',
  SESSION_EXPIRED = 'SESSION_EXPIRED',
  MAX_ATTEMPTS_REACHED = 'MAX_ATTEMPTS_REACHED',
}

export interface KYCContext {
  sessionId: string;
  userId: string;
  attempts: number;
  maxAttempts: number;
  expiresAt: Date;
  metadata: Record<string, any>;
}

export class KYCStateMachine extends EventEmitter {
  private currentState: KYCState = KYCState.NOT_INITIATED;
  private transitions: Record<KYCState, Record<KYCEvent, KYCState>>;

  constructor(private auditService: KYCAuditService) {
    super();
    this.initializeTransitions();
  }

  private initializeTransitions(): void {
    this.transitions = {
      [KYCState.NOT_INITIATED]: {
        [KYCEvent.START]: KYCState.CONSENT_PENDING,
      },
      [KYCState.CONSENT_PENDING]: {
        [KYCEvent.CONSENT_PROVIDED]: KYCState.OTP_GENERATION_PENDING,
      },
      [KYCState.OTP_GENERATION_PENDING]: {
        [KYCEvent.OTP_SENT_SUCCESS]: KYCState.OTP_SENT,
        [KYCEvent.OTP_SENT_FAILED]: KYCState.FAILED,
      },
      [KYCState.OTP_SENT]: {
        [KYCEvent.VERIFY_OTP]: KYCState.OTP_VERIFICATION_PENDING,
        [KYCEvent.SESSION_EXPIRED]: KYCState.EXPIRED,
        [KYCEvent.MAX_ATTEMPTS_REACHED]: KYCState.FAILED,
      },
      [KYCState.OTP_VERIFICATION_PENDING]: {
        [KYCEvent.VERIFICATION_SUCCESS]: KYCState.VERIFIED,
        [KYCEvent.VERIFICATION_FAILED]: KYCState.OTP_SENT,
        [KYCEvent.MAX_ATTEMPTS_REACHED]: KYCState.FAILED,
      },
      // Terminal states
      [KYCState.VERIFIED]: {},
      [KYCState.FAILED]: {},
      [KYCState.EXPIRED]: {},
    };
  }

  async transition(event: KYCEvent, context: KYCContext): Promise<KYCState> {
    const nextState = this.transitions[this.currentState]?.[event];

    if (!nextState) {
      throw new Error(
        `Invalid transition: ${this.currentState} + ${event}`
      );
    }

    const previousState = this.currentState;
    this.currentState = nextState;

    // Emit state change event
    this.emit('stateChange', {
      from: previousState,
      to: nextState,
      event,
      context,
    });

    // Audit the transition
    await this.auditService.logStateTransition({
      sessionId: context.sessionId,
      userId: context.userId,
      fromState: previousState,
      toState: nextState,
      event,
      timestamp: new Date(),
    });

    // Execute state-specific actions
    await this.executeStateActions(nextState, context);

    return nextState;
  }

  private async executeStateActions(
    state: KYCState,
    context: KYCContext
  ): Promise<void> {
    switch (state) {
      case KYCState.VERIFIED:
        this.emit('verification:success', context);
        break;
      case KYCState.FAILED:
        this.emit('verification:failed', context);
        break;
      case KYCState.EXPIRED:
        this.emit('session:expired', context);
        break;
    }
  }

  getCurrentState(): KYCState {
    return this.currentState;
  }

  reset(): void {
    this.currentState = KYCState.NOT_INITIATED;
  }
}
```

### 4. Type Definitions (`types/kyc.ts`)

```typescript
// Request/Response Types
export interface AadhaarOTPRequest {
  aadhaar_number: string;
  consent: {
    purpose: string;
    timestamp: string;
    version: string;
  };
  request_id?: string;
}

export interface AadhaarOTPResponse {
  session_id: string;
  masked_aadhaar: string;
  otp_sent_to: string;
  expires_at: string;
  attempts_remaining: number;
  request_id: string;
}

export interface AadhaarVerifyRequest {
  session_id: string;
  otp: string;
  share_code?: string;
}

export interface AadhaarVerifyResponse {
  verification_id: string;
  status: 'verified' | 'failed';
  kyc_data?: KYCData;
  verified_at: string;
}

// Data Types
export interface KYCData {
  reference_id: string;
  name: string;
  dob: string;
  gender: 'M' | 'F' | 'O';
  address: AadhaarAddress;
  photo?: string;
}

export interface AadhaarAddress {
  house: string;
  street: string;
  landmark: string;
  locality: string;
  vtc: string;
  district: string;
  state: string;
  pincode: string;
}

// Status Types
export interface KYCStatus {
  user_id: string;
  kyc_status: KYCStatusType;
  verification_levels: VerificationLevels;
  next_action?: string;
  last_updated: string;
}

export type KYCStatusType =
  | 'not_initiated'
  | 'in_progress'
  | 'verified'
  | 'failed'
  | 'expired';

export interface VerificationLevels {
  aadhaar?: VerificationLevel;
  pan?: VerificationLevel;
  bank_account?: VerificationLevel;
}

export interface VerificationLevel {
  status: 'verified' | 'pending' | 'not_initiated';
  verified_at?: string;
  expires_at?: string;
}

// Error Types
export interface KYCErrorResponse {
  error: {
    code: string;
    message: string;
    details?: any;
    retry_after?: number;
  };
}

// Session Types
export interface KYCSession {
  id: string;
  user_id: string;
  session_type: 'aadhaar' | 'pan' | 'bank';
  session_status: SessionStatus;
  masked_identifier?: string;
  created_at: Date;
  expires_at: Date;
  attempts: number;
  max_attempts: number;
  metadata?: Record<string, any>;
}

export type SessionStatus =
  | 'initiated'
  | 'otp_sent'
  | 'verified'
  | 'failed'
  | 'expired';

// Audit Types
export interface KYCAuditEntry {
  id: string;
  user_id: string;
  session_id?: string;
  action: string;
  action_status: 'success' | 'failure';
  ip_address?: string;
  user_agent?: string;
  request_data?: any;
  response_data?: any;
  error_details?: any;
  created_at: Date;
}
```

### 5. Integration with Main Service (`index.ts`)

```typescript
// Export KYC types
export * from './types/kyc';

// Export KYC service
export { default as createKYCService } from './services/kycService';

// Update main service factory
import createKYCService from './services/kycService';

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
  const kyc = createKYCService(apiClient); // New KYC service

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
    kyc, // Added KYC service
  };
};

export default createAAAService;
```

## Testing Strategy

### Unit Test Example

```typescript
// tests/unit/services/kycService.test.ts
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createKYCService } from '../../../services/kycService';

describe('KYC Service', () => {
  let apiClient: any;
  let kycService: ReturnType<typeof createKYCService>;

  beforeEach(() => {
    apiClient = {
      post: vi.fn(),
      get: vi.fn(),
    };
    kycService = createKYCService(apiClient);
  });

  describe('generateOTP', () => {
    it('should generate OTP successfully', async () => {
      const request = {
        aadhaar_number: '1234-5678-9012',
        consent: {
          purpose: 'KYC Verification',
          timestamp: new Date().toISOString(),
          version: '1.0',
        },
      };

      const mockResponse = {
        session_id: 'session-123',
        masked_aadhaar: 'XXXX-XXXX-9012',
        otp_sent_to: '******7890',
        expires_at: new Date(Date.now() + 600000).toISOString(),
        attempts_remaining: 3,
        request_id: 'req-123',
      };

      apiClient.post.mockResolvedValue(mockResponse);

      const result = await kycService.aadhaar.generateOTP(request);

      expect(apiClient.post).toHaveBeenCalledWith(
        '/api/v1/kyc/aadhaar/otp',
        request
      );
      expect(result).toEqual(mockResponse);
    });

    it('should handle invalid Aadhaar number', async () => {
      const request = {
        aadhaar_number: 'invalid',
        consent: {
          purpose: 'KYC Verification',
          timestamp: new Date().toISOString(),
          version: '1.0',
        },
      };

      apiClient.post.mockRejectedValue(
        new Error('Invalid Aadhaar number format')
      );

      await expect(
        kycService.aadhaar.generateOTP(request)
      ).rejects.toThrow('Invalid Aadhaar number format');
    });
  });

  describe('verifyOTP', () => {
    it('should verify OTP successfully', async () => {
      const request = {
        session_id: 'session-123',
        otp: '123456',
      };

      const mockResponse = {
        verification_id: 'verify-123',
        status: 'verified',
        kyc_data: {
          reference_id: 'ref-123',
          name: 'John Doe',
          dob: '1990-01-01',
          gender: 'M',
          address: {
            house: '123',
            street: 'Main St',
            landmark: 'Near Park',
            locality: 'Downtown',
            vtc: 'City',
            district: 'District',
            state: 'State',
            pincode: '123456',
          },
        },
        verified_at: new Date().toISOString(),
      };

      apiClient.post.mockResolvedValue(mockResponse);

      const result = await kycService.aadhaar.verifyOTP(request);

      expect(apiClient.post).toHaveBeenCalledWith(
        '/api/v1/kyc/aadhaar/otp/verify',
        request
      );
      expect(result).toEqual(mockResponse);
    });
  });

  describe('getStatus', () => {
    it('should get KYC status successfully', async () => {
      const userId = 'user-123';
      const mockResponse = {
        user_id: userId,
        kyc_status: 'verified',
        verification_levels: {
          aadhaar: {
            status: 'verified',
            verified_at: new Date().toISOString(),
            expires_at: new Date(Date.now() + 31536000000).toISOString(),
          },
        },
        last_updated: new Date().toISOString(),
      };

      apiClient.get.mockResolvedValue(mockResponse);

      const result = await kycService.status.get(userId);

      expect(apiClient.get).toHaveBeenCalledWith(
        `/api/v1/kyc/status/${userId}`
      );
      expect(result).toEqual(mockResponse);
    });
  });
});
```

## Migration Guide

### For Existing Auth Service Users

1. **Update package**:
   ```bash
   npm update auth-service
   ```

2. **Update imports**:
   ```typescript
   import createAAAService, { KYCStatus } from 'auth-service';
   ```

3. **Use KYC service**:
   ```typescript
   const service = createAAAService(config);

   // Generate OTP
   const otpResponse = await service.kyc.aadhaar.generateOTP({
     aadhaar_number: '1234-5678-9012',
     consent: {
       purpose: 'KYC Verification',
       timestamp: new Date().toISOString(),
       version: '1.0'
     }
   });

   // Verify OTP
   const verifyResponse = await service.kyc.aadhaar.verifyOTP({
     session_id: otpResponse.session_id,
     otp: '123456'
   });

   // Check status
   const status = await service.kyc.status.get(userId);
   ```

## Configuration

### Environment Configuration

```typescript
// config/environments/production.ts
export const kycConfig = {
  aadhaar: {
    gateway: {
      baseURL: process.env.AADHAAR_GATEWAY_URL,
      apiKey: process.env.AADHAAR_API_KEY,
      licenseKey: process.env.AADHAAR_LICENSE_KEY,
      encryptionKey: process.env.KYC_ENCRYPTION_KEY,
      timeout: 30000,
      retryConfig: {
        maxRetries: 3,
        backoffMultiplier: 2,
      },
    },
  },
  cache: {
    redis: {
      host: process.env.REDIS_HOST,
      port: parseInt(process.env.REDIS_PORT || '6379'),
      password: process.env.REDIS_PASSWORD,
      db: 1,
    },
  },
  rateLimits: {
    otpGeneration: {
      windowMs: 3600000, // 1 hour
      max: 3,
    },
    otpVerification: {
      windowMs: 900000, // 15 minutes
      max: 5,
    },
  },
  security: {
    sessionTTL: 600, // 10 minutes
    maxAttempts: 3,
    lockoutDuration: 86400, // 24 hours
  },
};
```

## CI/CD Integration

### GitHub Actions Workflow

```yaml
# .github/workflows/kyc-tests.yml
name: KYC Module Tests

on:
  push:
    paths:
      - 'services/kyc/**'
      - 'types/kyc.ts'
      - 'integrations/aadhaar/**'
      - 'tests/**/kyc/**'

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:14
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install dependencies
        run: npm ci

      - name: Run migrations
        run: npm run db:migrate

      - name: Run unit tests
        run: npm run test:unit -- services/kyc

      - name: Run integration tests
        run: npm run test:integration -- kyc

      - name: Run security tests
        run: npm run test:security -- kyc

      - name: Check coverage
        run: npm run coverage -- --threshold=90
```

## Documentation

### API Documentation (OpenAPI)

```yaml
# docs/api/kyc-api.yaml
openapi: 3.0.3
info:
  title: KYC Service API
  version: 1.0.0
  description: KYC and Aadhaar verification APIs

servers:
  - url: https://api.example.com/api/v1

paths:
  /kyc/aadhaar/otp:
    post:
      summary: Generate OTP for Aadhaar verification
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/AadhaarOTPRequest'
      responses:
        '200':
          description: OTP sent successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AadhaarOTPResponse'
        '400':
          $ref: '#/components/responses/BadRequest'
        '429':
          $ref: '#/components/responses/RateLimitExceeded'

  /kyc/aadhaar/otp/verify:
    post:
      summary: Verify Aadhaar OTP
      security:
        - bearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/AadhaarVerifyRequest'
      responses:
        '200':
          description: Verification successful
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AadhaarVerifyResponse'
        '400':
          $ref: '#/components/responses/BadRequest'

  /kyc/status/{userId}:
    get:
      summary: Get KYC verification status
      security:
        - bearerAuth: []
      parameters:
        - in: path
          name: userId
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: KYC status retrieved
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/KYCStatus'
        '404':
          $ref: '#/components/responses/NotFound'

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

  schemas:
    AadhaarOTPRequest:
      type: object
      required:
        - aadhaar_number
        - consent
      properties:
        aadhaar_number:
          type: string
          pattern: '^\d{4}-\d{4}-\d{4}$'
        consent:
          $ref: '#/components/schemas/Consent'
        request_id:
          type: string
          format: uuid

    Consent:
      type: object
      required:
        - purpose
        - timestamp
        - version
      properties:
        purpose:
          type: string
        timestamp:
          type: string
          format: date-time
        version:
          type: string

    # ... (additional schemas)
```

This project structure provides a comprehensive, scalable foundation for implementing KYC/Aadhaar validation APIs while maintaining the functional programming paradigm and zero-storage philosophy of the auth-service.
# KYC/Aadhaar Integration - Key Design Decisions

## Architecture Decision Record (ADR)

### ADR-001: Functional Programming with Zero Storage

**Status**: Accepted

**Context**: The auth-service follows a functional programming paradigm with zero storage dependencies at the library level.

**Decision**: KYC module will maintain the same architectural principles:
- Pure functions without side effects
- No direct storage mechanisms (no localStorage, sessionStorage, or database)
- Configuration injection pattern for all external dependencies
- Downstream applications handle all state management

**Consequences**:
- ✅ Maximum flexibility for consuming applications
- ✅ Easier testing without mocking storage
- ✅ Platform agnostic (works in Node.js, browsers, React Native)
- ⚠️ Requires careful documentation for integration
- ⚠️ Consumers must implement their own storage strategy

**Rationale**: Consistency with existing architecture ensures maintainability and predictable behavior across the entire auth-service ecosystem.

---

### ADR-002: Tokenization Over Encryption for Aadhaar Storage

**Status**: Accepted

**Context**: UIDAI regulations prohibit storing Aadhaar numbers in any retrievable form. Two approaches exist:
1. Field-level encryption with key rotation
2. One-way tokenization with secure vault

**Decision**: Implement tokenization using HMAC-SHA256 with a dedicated tokenization key:
```typescript
const token = HMAC-SHA256(aadhaarNumber + salt, tokenizationKey)
```

**Consequences**:
- ✅ Aadhaar number cannot be retrieved from token
- ✅ Deterministic tokens enable duplicate detection
- ✅ Simpler key management (one tokenization key vs multiple DEKs)
- ⚠️ Original Aadhaar needed for re-verification
- ⚠️ Requires secure vault for token-to-reference mapping

**Rationale**: Tokenization provides stronger compliance with UIDAI's non-storage requirement while maintaining ability to detect duplicate verifications.

---

### ADR-003: State Machine for KYC Workflow

**Status**: Accepted

**Context**: KYC verification involves multiple steps with complex state transitions and business rules.

**Decision**: Implement explicit state machine pattern using XState/custom implementation:
- Defined states: NOT_INITIATED → CONSENT → OTP_SENT → VERIFIED/FAILED
- Explicit transitions with guards
- Side effects handled separately
- Audit trail for all state changes

**Consequences**:
- ✅ Business logic is explicit and testable
- ✅ Prevents invalid state transitions
- ✅ Easy to visualize and document flows
- ✅ Natural audit points at transitions
- ⚠️ Additional complexity for simple flows
- ⚠️ Learning curve for developers

**Rationale**: Complex compliance requirements and multiple failure modes make explicit state management essential for maintainability and correctness.

---

### ADR-004: Circuit Breaker Pattern for External Services

**Status**: Accepted

**Context**: UIDAI and other KYC providers may experience outages or degraded performance.

**Decision**: Implement circuit breaker with three states:
- **CLOSED**: Normal operation
- **OPEN**: Fast fail after threshold breaches (5 failures in 2 minutes)
- **HALF_OPEN**: Test recovery with limited requests

**Configuration**:
```typescript
{
  failureThreshold: 5,
  resetTimeout: 60000,        // 1 minute
  monitoringPeriod: 120000,   // 2 minutes
  halfOpenRequests: 3
}
```

**Consequences**:
- ✅ Prevents cascading failures
- ✅ Faster recovery detection
- ✅ Better user experience during outages
- ⚠️ May reject valid requests during recovery
- ⚠️ Requires careful threshold tuning

**Rationale**: External dependency failures should not bring down the entire system. Fast-fail improves user experience over timeouts.

---

### ADR-005: Multi-Tier Caching Strategy

**Status**: Accepted

**Context**: KYC verification results need to be cached for performance while respecting data sensitivity.

**Decision**: Implement two-tier caching:
1. **L1 Cache** (In-memory): 5-minute TTL for session data
2. **L2 Cache** (Redis): 24-hour TTL for verification status only

**Cache Content Policy**:
- ✅ Cache: Verification status, session IDs, rate limit counters
- ❌ Don't Cache: PII data, Aadhaar numbers, KYC documents

**Consequences**:
- ✅ Reduced latency for status checks
- ✅ Lower load on database
- ✅ Compliance with data minimization
- ⚠️ Cache invalidation complexity
- ⚠️ Additional infrastructure (Redis)

**Rationale**: Performance requirements necessitate caching, but security and compliance limit what can be cached.

---

### ADR-006: Audit Logging with Blockchain-Style Chaining

**Status**: Accepted

**Context**: UIDAI requires tamper-proof audit logs maintained for 7 years.

**Decision**: Implement audit logs with hash chaining:
```typescript
currentLog.hash = SHA256(currentLog.content + previousLog.hash)
```

**Implementation**:
- Each log entry includes hash of previous entry
- Periodic checkpoints stored in immutable storage
- Real-time streaming to SIEM
- Async write to ensure performance

**Consequences**:
- ✅ Tamper detection capability
- ✅ Regulatory compliance
- ✅ Court-admissible evidence
- ⚠️ Cannot delete or modify logs
- ⚠️ Storage growth over 7 years

**Rationale**: Regulatory requirements and security best practices demand tamper-evident audit trails.

---

### ADR-007: Rate Limiting at Multiple Levels

**Status**: Accepted

**Context**: Prevent abuse while allowing legitimate usage patterns.

**Decision**: Implement hierarchical rate limiting:
1. **Global**: 1000 requests/15min per IP
2. **OTP Generation**: 3 requests/hour per user
3. **OTP Verification**: 5 attempts/session
4. **Status Checks**: 10 requests/minute per user

**Implementation**: Token bucket algorithm with Redis backend

**Consequences**:
- ✅ Prevents brute force attacks
- ✅ Controls infrastructure costs
- ✅ Fair resource allocation
- ⚠️ May impact legitimate burst usage
- ⚠️ Requires Redis for distributed limiting

**Rationale**: Multiple levels provide fine-grained control while preventing both DoS attacks and Aadhaar farming.

---

### ADR-008: Consent Management as First-Class Citizen

**Status**: Accepted

**Context**: DPDP Act and Aadhaar Act require explicit consent for data processing.

**Decision**: Implement consent as mandatory parameter with:
- Versioned consent templates
- Purpose limitation enforcement
- Consent withdrawal mechanism
- Audit trail of all consent actions

**Schema**:
```typescript
interface Consent {
  purpose: string;
  version: string;      // Minimum "2.1" per UIDAI
  timestamp: ISO8601;
  informedConsent: boolean;
  dataSharing: string[];
  retentionPeriod: number;
}
```

**Consequences**:
- ✅ Legal compliance
- ✅ User trust and transparency
- ✅ Clear audit trail
- ⚠️ Additional API complexity
- ⚠️ Consent version management

**Rationale**: Legal requirement with significant penalties for non-compliance.

---

### ADR-009: Graceful Degradation Strategy

**Status**: Accepted

**Context**: System should remain partially functional during component failures.

**Decision**: Implement fallback mechanisms:
1. **Primary Provider Failure**: Route to backup KYC provider
2. **Cache Failure**: Continue with direct database access
3. **Audit Failure**: Queue logs for later processing
4. **Rate Limit Failure**: Apply conservative defaults

**Consequences**:
- ✅ Higher availability
- ✅ Better user experience
- ⚠️ Increased complexity
- ⚠️ Potential for degraded performance

**Rationale**: Critical business function requires maximum availability even with reduced functionality.

---

### ADR-010: Provider Abstraction Layer

**Status**: Accepted

**Context**: Multiple KYC providers (UIDAI, DigiLocker, third-party) with different APIs.

**Decision**: Implement provider interface:
```typescript
interface KYCProvider {
  generateOTP(identifier: string): Promise<OTPResponse>;
  verifyOTP(session: string, otp: string): Promise<VerifyResponse>;
  getCapabilities(): ProviderCapabilities;
}
```

**Consequences**:
- ✅ Easy to add new providers
- ✅ A/B testing capability
- ✅ Vendor independence
- ⚠️ Abstraction overhead
- ⚠️ Feature parity challenges

**Rationale**: Avoid vendor lock-in and enable multi-provider strategies for resilience.

---

## Trade-off Analysis

### Performance vs Security

| Aspect | Performance Optimized | Security Optimized | Our Choice |
|--------|----------------------|-------------------|------------|
| Encryption | Symmetric only | Asymmetric + Symmetric | Symmetric with HSM |
| Session Duration | 30 minutes | 5 minutes | 10 minutes |
| Cache TTL | 1 hour | No caching | 5 min L1, 24hr L2 (status only) |
| Rate Limits | 10 req/sec | 1 req/min | Tiered approach |

### Cost vs Compliance

| Component | Cost Optimized | Compliance Optimized | Our Choice |
|-----------|---------------|---------------------|------------|
| Audit Storage | 90 days | 7 years | 7 years with archival |
| Encryption | Software | HSM | HSM for production |
| Monitoring | Basic logs | Full SIEM | SIEM + custom alerts |
| Testing | Manual | Automated + Pentesting | Quarterly automated + Annual pentest |

---

## Risk Registry

### High Risks

1. **Data Breach of Aadhaar Data**
   - Mitigation: Tokenization, encryption, access controls
   - Residual Risk: LOW

2. **Regulatory Non-Compliance**
   - Mitigation: Regular audits, compliance checklist
   - Residual Risk: MEDIUM

3. **Service Availability**
   - Mitigation: Circuit breakers, multi-provider strategy
   - Residual Risk: MEDIUM

### Medium Risks

1. **Rate Limit Bypass**
   - Mitigation: Distributed rate limiting, IP reputation
   - Residual Risk: LOW

2. **Session Hijacking**
   - Mitigation: Short sessions, device binding, MFA
   - Residual Risk: LOW

3. **Audit Log Tampering**
   - Mitigation: Hash chaining, immutable storage
   - Residual Risk: LOW

---

## Implementation Priority

### Phase 1 - Core (Weeks 1-2)
1. Type definitions and interfaces
2. Basic service structure
3. Provider abstraction
4. State machine implementation

### Phase 2 - Security (Weeks 3-4)
1. Encryption service
2. Tokenization implementation
3. Audit logging
4. Rate limiting

### Phase 3 - Integration (Weeks 5-6)
1. UIDAI gateway integration
2. Circuit breaker implementation
3. Cache layer
4. Error handling

### Phase 4 - Compliance (Weeks 7-8)
1. Consent management
2. Data retention policies
3. Security headers
4. Monitoring integration

### Phase 5 - Hardening (Weeks 9-10)
1. Performance optimization
2. Security testing
3. Documentation
4. Deployment preparation

---

## Success Metrics

### Technical Metrics
- API response time < 2 seconds (p95)
- Availability > 99.9%
- Zero security breaches
- Audit log integrity 100%

### Business Metrics
- OTP verification success rate > 95%
- User session completion > 90%
- Support ticket reduction > 30%
- Compliance score 100%

### Security Metrics
- Zero OWASP Top 10 vulnerabilities
- 100% encryption coverage for PII
- Audit trail completeness 100%
- Incident response time < 15 minutes

---

## Review and Approval

| Stakeholder | Role | Status | Date |
|------------|------|--------|------|
| Security Team | Security Review | Pending | - |
| Legal Team | Compliance Review | Pending | - |
| Architecture Board | Technical Review | Pending | - |
| Product Owner | Business Approval | Pending | - |

---

## References

1. [UIDAI API Specification v2.5](https://uidai.gov.in/images/resource/aadhaar_authentication_api_2_5.pdf)
2. [Digital Personal Data Protection Act 2023](https://www.meity.gov.in/dpdp-act-2023)
3. [OWASP ASVS 4.0](https://owasp.org/www-project-application-security-verification-standard/)
4. [RBI KYC Master Direction](https://www.rbi.org.in/Scripts/BS_ViewMasDirections.aspx?id=11566)
5. [ISO 27001:2022](https://www.iso.org/standard/27001)

---

**Document Status**: DRAFT
**Version**: 1.0
**Last Updated**: November 2024
**Next Review**: December 2024
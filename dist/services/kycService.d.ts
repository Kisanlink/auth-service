import createApiClient from '../utils/apiClient';
import { AadhaarOTPRequest, AadhaarOTPResponse, AadhaarVerifyRequest, AadhaarVerifyResponse, KYCStatus } from '../types';
/**
 * Factory function to create a KYC service with injectable API client
 * Provides KYC/Aadhaar verification capabilities following functional programming principles
 *
 * @param apiClient - API client instance for making HTTP requests
 * @returns KYC service object with aadhaar and status operations
 *
 * @example
 * ```typescript
 * const apiClient = createApiClient({ baseURL: 'https://api.example.com' });
 * const kycService = createKYCService(apiClient);
 *
 * // Generate OTP for Aadhaar verification
 * const otpResponse = await kycService.aadhaar.generateOTP({
 *   aadhaar_number: '1234-5678-9012',
 *   consent: {
 *     purpose: 'KYC Verification',
 *     timestamp: new Date().toISOString(),
 *     version: '1.0'
 *   }
 * });
 *
 * // Verify OTP
 * const verifyResponse = await kycService.aadhaar.verifyOTP({
 *   session_id: otpResponse.session_id,
 *   otp: '123456'
 * });
 *
 * // Check KYC status
 * const status = await kycService.status.get('user-123');
 * ```
 */
declare const createKYCService: (apiClient: ReturnType<typeof createApiClient>) => {
    /**
     * Aadhaar verification operations
     */
    aadhaar: {
        /**
         * Generate OTP for Aadhaar verification
         *
         * Initiates the Aadhaar verification process by generating and sending an OTP
         * to the mobile number registered with the provided Aadhaar number.
         *
         * @param request - Aadhaar OTP request containing aadhaar number and consent
         * @returns Promise resolving to OTP response with session ID and masked details
         *
         * @throws {Error} When Aadhaar number format is invalid (400)
         * @throws {Error} When rate limit is exceeded (429)
         * @throws {Error} When external service is unavailable (503)
         *
         * Security considerations:
         * - Aadhaar number is never logged in plain text
         * - Consent must be explicitly provided with purpose and timestamp
         * - Rate limiting is enforced to prevent abuse
         * - Session expires in 10 minutes (600 seconds)
         */
        generateOTP: (request: AadhaarOTPRequest) => Promise<AadhaarOTPResponse>;
        /**
         * Verify Aadhaar OTP and retrieve KYC data
         *
         * Verifies the OTP sent to the user's registered mobile number and returns
         * the KYC data from UIDAI if verification is successful.
         *
         * @param request - OTP verification request with session ID and OTP
         * @returns Promise resolving to verification response with KYC data if successful
         *
         * @throws {Error} When session ID is invalid or expired (400)
         * @throws {Error} When OTP is incorrect (400)
         * @throws {Error} When maximum verification attempts exceeded (400)
         *
         * Security considerations:
         * - OTP is single-use and expires after verification attempt
         * - Maximum 3 verification attempts per session
         * - KYC data includes sensitive PII - handle with care
         * - Optional share_code for eKYC with photo
         *
         * @example
         * ```typescript
         * const result = await kycService.aadhaar.verifyOTP({
         *   session_id: 'session-uuid',
         *   otp: '123456',
         *   share_code: '1234' // Optional for photo
         * });
         *
         * if (result.status === 'verified') {
         *   console.log('KYC verified:', result.kyc_data);
         * }
         * ```
         */
        verifyOTP: (request: AadhaarVerifyRequest) => Promise<AadhaarVerifyResponse>;
    };
    /**
     * KYC status operations
     */
    status: {
        /**
         * Get KYC verification status for a user
         *
         * Retrieves the complete KYC verification status including all verification
         * levels (Aadhaar, PAN, Bank Account) and their current states.
         *
         * @param userId - User ID to check KYC status for
         * @returns Promise resolving to KYC status with all verification levels
         *
         * @throws {Error} When user ID is not found (404)
         * @throws {Error} When user is not authorized to access this resource (403)
         *
         * @example
         * ```typescript
         * const status = await kycService.status.get('user-123');
         *
         * console.log('Overall KYC status:', status.kyc_status);
         * console.log('Aadhaar verified:', status.verification_levels.aadhaar?.status);
         * console.log('Next action:', status.next_action);
         * ```
         */
        get: (userId: string) => Promise<KYCStatus>;
    };
};
export default createKYCService;

import { describe, it } from 'vitest';
import { authServiceClient } from '../../services/authService';

// These tests assume a reachable AAA v2 backend via env var baseURL.
// They are structured as integration flow placeholders and can be filled with real credentials in CI.

describe('AuthService integration flows', () => {
  it.skip('login -> evaluatePermission -> refresh -> logout', async () => {
    // Provide test credentials via env when enabling this test
    const country_code = process.env.TEST_CC || '+91';
    const phone_number = process.env.TEST_PHONE || '0000000000';
    const password = process.env.TEST_PASSWORD || 'secret';

    const loginRes = await authServiceClient.login({ country_code, phone_number, password });
    if (!loginRes.success) throw new Error('login failed');

    const userId = loginRes.data.user.id;
    const evalRes = await authServiceClient.evaluatePermission({ user_id: userId, permission: 'dashboard:view' });
    if (!evalRes.success) throw new Error('permission evaluation failed');

    const refreshRes = await authServiceClient.refresh({ mpin: '1234', refresh_token: loginRes.data.refresh_token });
    if (!refreshRes.success) throw new Error('refresh failed');

    const logoutRes = await authServiceClient.logout();
    if (!logoutRes.success) throw new Error('logout failed');
  });
});






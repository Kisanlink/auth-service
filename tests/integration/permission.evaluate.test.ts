import { describe, it } from 'vitest';
import { authServiceClient } from '../../services/authService';

describe('Permission evaluation user flow', () => {
  it.skip('evaluates a known permission for a known user', async () => {
    const user_id = process.env.TEST_USER_ID || '';
    if (!user_id) throw new Error('set TEST_USER_ID to run this');
    const res = await authServiceClient.evaluatePermission({ user_id, permission: 'dashboard:view' });
    if (!res.success) throw new Error('evaluation failed');
  });
});






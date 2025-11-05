import { describe, it } from 'vitest';
import { userServiceClient } from '../../services/userService';

// These are smoke tests for the userService client.
// They are skipped by default and can be enabled in CI with real env/fixtures.

describe('userService client (integration)', () => {
  it.skip('lists users', async () => {
    const res = await userServiceClient.list({ limit: 5, offset: 0 } as any);
    if (!(res as any).success) throw new Error('list failed');
  });

  it.skip('gets user by id', async () => {
    const testUserId = process.env.TEST_USER_ID || '';
    if (!testUserId) throw new Error('set TEST_USER_ID');
    const res = await userServiceClient.getById(testUserId);
    if (!(res as any).success) throw new Error('getById failed');
  });

  it.skip('assigns and removes role', async () => {
    const testUserId = process.env.TEST_USER_ID || '';
    const testRoleId = process.env.TEST_ROLE_ID || '';
    if (!testUserId || !testRoleId) throw new Error('set TEST_USER_ID and TEST_ROLE_ID');
    const assignRes = await userServiceClient.assignRole(testUserId, testRoleId);
    if (!(assignRes as any).success) throw new Error('assignRole failed');
    const removeRes = await userServiceClient.removeRole(testUserId, testRoleId);
    if (!(removeRes as any).success) throw new Error('removeRole failed');
  });
});






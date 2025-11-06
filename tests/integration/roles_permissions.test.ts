import { describe, it } from 'vitest';
import { roleServiceClient } from '../../services/roleService';
import { permissionServiceClient } from '../../services/permissionService';

describe('roleService and permissionService (integration)', () => {
  it.skip('lists roles', async () => {
    const res = await roleServiceClient.list({ limit: 5, offset: 0 } as any);
    if (!(res as any).success) throw new Error('list roles failed');
  });

  it.skip('creates and deletes a role', async () => {
    const name = `test_role_${Date.now()}`;
    const createRes = await roleServiceClient.create({ name, description: 'tmp' } as any);
    if (!(createRes as any).success) throw new Error('create role failed');
    const id = (createRes as any).data?.id;
    if (!id) throw new Error('no role id');
    const delRes = await roleServiceClient.delete(id);
    if (!(delRes as any).success) throw new Error('delete role failed');
  });

  it.skip('evaluates a permission', async () => {
    const user_id = process.env.TEST_USER_ID || '';
    if (!user_id) throw new Error('set TEST_USER_ID');
    const res = await permissionServiceClient.evaluate({ user_id, permission: 'dashboard:view' } as any);
    if (!(res as any).success) throw new Error('evaluate failed');
  });
});






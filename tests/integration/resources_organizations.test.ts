import { describe, it } from 'vitest';
import { resourceServiceClient } from '../../services/resourceService';
import { organizationServiceClient } from '../../services/organizationService';

describe('resourceService and organizationService (integration)', () => {
  it.skip('lists resources', async () => {
    const res = await resourceServiceClient.list({ limit: 5, offset: 0 } as any);
    if (!(res as any).success) throw new Error('list resources failed');
  });

  it.skip('gets organization hierarchy', async () => {
    const orgId = process.env.TEST_ORG_ID || '';
    if (!orgId) throw new Error('set TEST_ORG_ID');
    const res = await organizationServiceClient.getHierarchy(orgId);
    if (!(res as any).success) throw new Error('getHierarchy failed');
  });

  it.skip('lists organization groups', async () => {
    const orgId = process.env.TEST_ORG_ID || '';
    if (!orgId) throw new Error('set TEST_ORG_ID');
    const res = await organizationServiceClient.listGroups(orgId, { limit: 5, offset: 0 });
    if (!(res as any).success) throw new Error('listGroups failed');
  });
});






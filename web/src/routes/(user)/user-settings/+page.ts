import { getApiKeys, getPublicConfig, getSessions, searchPasskeys } from '@immich/sdk';
import { authenticate } from '$lib/utils/auth';
import { getFormatter } from '$lib/utils/i18n';
import type { PageLoad } from './$types';

export const load = (async ({ url }) => {
  await authenticate(url);

  const keys = await getApiKeys();
  const sessions = await getSessions();
  const passkeys = await searchPasskeys({});
  const publicConfig = await getPublicConfig();
  const $t = await getFormatter();

  return {
    keys,
    sessions,
    passkeys,
    publicConfig,
    meta: {
      title: $t('settings'),
    },
  };
}) satisfies PageLoad;

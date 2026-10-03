import deploymentData from './deployment-data.json' with { type: 'json' };
import { createProvider } from './handler.mjs';

const provider = createProvider(deploymentData);

export default {
  fetch: provider.fetch,
};

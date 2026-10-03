import deploymentData from './deployment-data.json' with { type: 'json' };
import { createProvider } from './handler.mjs';
import { createExpiryMaintenance } from './maintenance.mjs';

const provider = createProvider(deploymentData);
const maintenance = createExpiryMaintenance(deploymentData);

export default {
  fetch: provider.fetch,
  scheduled(controller, _env, ctx) {
    ctx.waitUntil(maintenance.run(controller).then(result => {
      console.log(JSON.stringify(result));
    }));
  },
};

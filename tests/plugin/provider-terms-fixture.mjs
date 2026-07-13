import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import { validateProviderTermsCatalog } from "../../lib/provider-terms.mjs";

const catalog = validateProviderTermsCatalog(JSON.parse(await readFile(
  "skills/data-broker-removal/references/brokers/provider-terms.json", "utf8",
)));

export function publisherAutomationPermissions(brokerIds, {
  allowedEffects = ["source_refresh", "publisher_discover", "direct_recheck", "submit_form", "open_verification"],
  allowedBrowserBackends = ["managed_openclaw", "remote_cloud_cdp", "existing_logged_in_cdp"],
} = {}) {
  return Object.fromEntries(brokerIds.map((brokerId) => {
    const contract = catalog.brokers.find((entry) => entry.id === brokerId);
    if (!contract) throw new Error(`missing_test_provider_terms:${brokerId}`);
    return [brokerId, {
      authorizationReferenceSha256: createHash("sha256").update(`test-written-provider-authorization:${brokerId}`).digest("hex"),
      termsContractDigest: contract.contract_digest,
      reviewedAt: "2026-07-13T00:00:00.000Z",
      validUntil: "2027-07-12T00:00:00.000Z",
      allowedEffects: [...allowedEffects],
      allowedBrowserBackends: [...allowedBrowserBackends],
    }];
  }));
}

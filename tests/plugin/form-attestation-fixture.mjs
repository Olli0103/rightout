import { removalProfileDigest } from "../../lib/removal.mjs";

export function formAttestations(profileId, profilePayload, brokerIds) {
  return {
    rightoutFormPolicyAccepted: true,
    rightoutFormPolicyVersion: "2026-07-12",
    subjectConsentReviewed: true,
    browserFormAuthorized: true,
    minimumDisclosureAccepted: true,
    authorizedProfileIds: [profileId],
    authorizedProfileDigests: { [profileId]: removalProfileDigest(profilePayload) },
    authorizedBrokerIds: [...new Set(brokerIds)].sort(),
  };
}

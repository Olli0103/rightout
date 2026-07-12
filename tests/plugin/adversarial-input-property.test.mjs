import assert from "node:assert/strict";
import test from "node:test";

import { validatePublicToolInput } from "../../lib/live-scan.mjs";
import { validateRemovalPublicToolInput } from "../../lib/removal.mjs";
import { validateFormRemovalInput } from "../../lib/form-removal.mjs";
import { validateDirectScanInput } from "../../lib/direct-rescan.mjs";
import { validateVerificationOpenInput, validateVerificationPollInput } from "../../lib/verification.mjs";

const hostile = [
  "", ".", "..", "../escape", "a/b", "a\\b", "A".repeat(4096),
  "profile_0123456789abcdef\u0000", "profile_0123456789abcdef?x=1",
  "${RIGHTOUT_SECRET}", "https://example.invalid", " Avery Example ",
  "profile_💣💣💣💣💣💣💣💣", "profile_0123456789ABCDEf",
];

test("public validators reject adversarial opaque-reference substitutions", () => {
  const validProfile = "profile_0123456789abcdef";
  const validators = [
    (value) => validatePublicToolInput({ profileId: value, brokerIds: ["beenverified"] }),
    (value) => validateRemovalPublicToolInput({ profileId: value, brokerId: "beenverified", requestKind: "delete_and_opt_out" }),
    (value) => validateFormRemovalInput({ profileId: value, brokerId: "intelius", requestKind: "delete_and_opt_out" }),
    (value) => validateDirectScanInput({ profileId: value, brokerId: "beenverified", listingHandle: "listing_0123456789abcdef01234567" }),
    (value) => validateVerificationPollInput({ profileId: value, brokerId: "beenverified" }),
    (value) => validateVerificationOpenInput({ profileId: value, brokerId: "beenverified", verificationHandle: "verify_0123456789abcdef01234567" }),
  ];
  for (const validate of validators) {
    for (const value of hostile) assert.throws(() => validate(value));
  }
  assert.equal(validatePublicToolInput({ profileId: validProfile, brokerIds: ["beenverified"] }).profileId, validProfile);
});

test("broker and handle fields reject traversal, URLs, Unicode, and overlong values", () => {
  const profileId = "profile_0123456789abcdef";
  for (const value of hostile) {
    assert.throws(() => validateRemovalPublicToolInput({ profileId, brokerId: value, requestKind: "delete_and_opt_out" }));
    assert.throws(() => validateDirectScanInput({ profileId, brokerId: "beenverified", listingHandle: value }));
    assert.throws(() => validateVerificationOpenInput({ profileId, brokerId: "beenverified", verificationHandle: value }));
  }
});

test("unknown keys and type substitutions fail closed across public contracts", () => {
  const profileId = "profile_0123456789abcdef";
  for (const replacement of [null, false, true, 0, 1, [], {}, { toString() { return profileId; } }]) {
    assert.throws(() => validatePublicToolInput({ profileId: replacement, brokerIds: ["beenverified"] }));
  }
  assert.throws(() => validatePublicToolInput({ profileId, brokerIds: ["beenverified"], fullName: "Avery Example" }));
  assert.throws(() => validateRemovalPublicToolInput({ profileId, brokerId: "beenverified", requestKind: "delete_and_opt_out", recipient: "attacker@example.invalid" }));
});

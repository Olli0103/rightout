import assert from "node:assert/strict";
import test from "node:test";

import { buildEffectivenessReport } from "../../lib/effectiveness.mjs";

const profileId = "profile_0123456789abcdef";
const cases = [
  { broker_id: "alpha", state: "found", listing_handle: "listing_0123456789abcdef01234567" },
  { broker_id: "bravo", state: "submitted", listing_handle: null },
  { broker_id: "charlie", state: "confirmed_removed", listing_handle: null },
  { broker_id: "delta", state: "inconclusive", listing_handle: null },
  { broker_id: "echo", state: "reappeared", listing_handle: null },
];
const status = {
  report_version: 1,
  subject_ref: profileId,
  generated_at: "2026-07-14T12:00:00.000Z",
  cases,
};

test("effectiveness keeps capability separate from operational proof and exposes denominators", () => {
  const report = buildEffectivenessReport(status);
  assert.equal(report.target_count, 5);
  assert.deepEqual(report.discovery.signal_rate, { numerator: 4, denominator: 5, rate: 0.8 });
  assert.deepEqual(report.submission.rate_from_discovery, { numerator: 3, denominator: 4, rate: 0.75 });
  assert.deepEqual(report.provider_confirmation.rate_from_submission, { numerator: 2, denominator: 3, rate: 0.6667 });
  assert.deepEqual(report.reappearance.rate_from_confirmation, { numerator: 1, denominator: 2, rate: 0.5 });
  assert.equal(report.operational_effectiveness, "needs_evidence");
  assert.equal(report.invariants.technical_capability_used_as_effectiveness_proof, false);
  assert.equal(report.invariants.missing_denominators_hidden, false);
});

test("only scoped authorized canary facts can evidence operational effectiveness", () => {
  const report = buildEffectivenessReport(status, [{
    profileId,
    brokerId: "charlie",
    kind: "direct_absence",
    observedAt: "2026-07-14T11:30:00.000Z",
    proofReference: "canary_0123456789abcdef01234567",
  }]);
  assert.equal(report.operational_effectiveness, "evidenced_by_authorized_canaries");
  assert.equal(report.authorized_canaries.by_kind.direct_absence, 1);
  assert.deepEqual(report.authorized_canaries.proof_references, ["canary_0123456789abcdef01234567"]);
  assert.doesNotMatch(JSON.stringify(report), /@|https?:\/\//u);
});

test("effectiveness rejects cross-profile, unknown-broker, duplicate, and malformed canaries", () => {
  const base = {
    profileId,
    brokerId: "alpha",
    kind: "controller_confirmed",
    observedAt: "2026-07-14T11:30:00.000Z",
    proofReference: "canary_0123456789abcdef01234567",
  };
  assert.throws(() => buildEffectivenessReport(status, [{ ...base, profileId: "profile_ffffffffffffffff" }]), /canary_invalid/);
  assert.throws(() => buildEffectivenessReport(status, [{ ...base, brokerId: "unknown" }]), /canary_invalid/);
  assert.throws(() => buildEffectivenessReport(status, [base, { ...base, brokerId: "bravo" }]), /canary_invalid/);
  assert.throws(() => buildEffectivenessReport(status, [{ ...base, proofReference: "raw-proof" }]), /canary_invalid/);
  assert.throws(() => buildEffectivenessReport(status, [{ ...base, brokerId: "bravo" }]), /state_conflict/);
  assert.throws(() => buildEffectivenessReport(status, [{ ...base, observedAt: "2026-07-14T12:30:00.000Z" }]), /state_conflict/);
});

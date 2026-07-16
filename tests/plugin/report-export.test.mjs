import assert from "node:assert/strict";
import test from "node:test";

import { createReportExport } from "../../lib/report-export.mjs";

test("status export emits Markdown, structured JSON, and Google Sheets-compatible rows without PII", () => {
  const report = createReportExport({
    subject_ref: "profile_0123456789abcdef",
    counts: { submitted: 1, confirmed_removed: 0 },
    metrics: { confirmed_removed: 0, in_flight: 1, needs_reconciliation: 0, human_tasks: 0 },
    cases: [{
      broker_id: "spokeo", state: "submitted", submission_channel: "browser_webmail",
      next_recheck_at: "2026-08-27T00:00:00.000Z", removal_confirmation_scope: null,
      coverage_gap: "new_or_unindexed_listing_urls_not_checked", proof_references: ["webmail_opaque"],
    }],
    preference_controls: [{
      control_id: "global_privacy_control",
      state: "enabled_human_verified",
      deletion_request: false,
      deletion_confirmed: false,
      browser_configuration_performed_by_rightout: false,
      provider_compliance: "needs_evidence_per_site",
    }],
  }, { generatedAt: "2026-07-13T12:00:00.000Z" });
  assert.match(report.markdown, /# RightOut status/);
  assert.deepEqual(report.google_sheets_rows[0], ["subject_ref", "broker_id", "state", "submission_channel", "next_recheck_at", "confirmation_scope", "coverage_gap"]);
  assert.equal(report.google_sheets_rows[1][1], "spokeo");
  assert.equal(report.google_sheets_range, "Sheet1!A1:G2");
  assert.equal(report.structured.preference_controls[0].deletion_confirmed, false);
  assert.match(report.markdown, /Preference signals are not deletion requests or deletion proof/);
  assert.equal(report.raw_pii_in_report, false);
  assert.equal(JSON.stringify(report).includes("Avery"), false);
});

test("status export rejects any preference record that claims deletion", () => {
  assert.throws(() => createReportExport({
    subject_ref: "profile_0123456789abcdef",
    counts: {},
    metrics: {},
    cases: [],
    preference_controls: [{
      control_id: "global_privacy_control",
      state: "enabled_human_verified",
      deletion_request: false,
      deletion_confirmed: true,
      browser_configuration_performed_by_rightout: false,
      provider_compliance: "needs_evidence_per_site",
    }],
  }), /rightout_report_state_invalid/);
});

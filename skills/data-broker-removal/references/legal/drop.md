# California DROP Notes

California DROP source: `https://privacy.ca.gov/drop/`

Key operational facts verified 2026-07-16:

- DROP is for California residents.
- It lets eligible users tell data brokers to delete and not sell personal information.
- Filing uses California's human identity and residency flow; RightOut never logs in or supplies identity proof.
- DROP launches January 1, 2026; brokers begin processing requests August 1, 2026.
- The official consumer guidance says brokers have 90 days to process a request.
- The official broker guidance requires access and processing at least every 45 days.
- Portal status becomes available from August 2026.

OpenClaw rule: treat filing and status inspection as `human_only`. After a
person verifies the filing, `rightout_record_drop_filed` records the registry
scope, phase, first checkpoint, and ordinary 90-day deadline. After a person
checks the portal, `rightout_record_drop_status` records only `pending`,
`deleted`, or `needs_manual_check`.

Even `deleted` is a human-observed government-portal claim, not direct
record-level deletion proof. It must never set `confirmed_removed`, a
confirmation scope, or GPC/site compliance. Non-registered brokers, FCRA data,
records outside the platform's scope, and future reappearance remain gaps.

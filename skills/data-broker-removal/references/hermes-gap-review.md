# Historical Hermes `unbroker` gap review

Hermes `unbroker` was reviewed as a workflow reference on 2026-07-11. No Hermes code, prose, or broker dataset is copied into RightOut.

Useful product categories retained in RightOut's synthetic report model include exposure states, removal lifecycle states, reappearance, least disclosure, human blockers, and later verification.

RightOut deliberately differs:

- live capability is a single optional read-only scan tool, not autonomous removal;
- raw PII is referenced through OpenClaw SecretRefs, not model parameters or runner files;
- every live call uses native allow-once/deny approval;
- no email, form, CAPTCHA, verification-link, scheduler, HIBP account query, or provider write exists;
- catalog records are independently authored from official sources and do not import BADBOOL-derived data;
- live negatives remain inconclusive unless direct absence evidence exists (not currently implemented).

Any future removal capability requires a separate goal, tool, approval, policy, terms/legal review, retention design, and independent security review.

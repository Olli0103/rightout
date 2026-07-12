# RightOut v0.7.1

RightOut 0.7.1 is a security patch for four CodeQL findings discovered during
the final post-publication verification of v0.7.0. Credential-bound SMTP and
IMAP snapshot digests now use domain-separated `scrypt`; verification-link
entities decode exactly once; and direct-rescan HTML is converted to bounded
visible text by a parser instead of regular-expression tag stripping.

The broker catalog, approval model, tool set, and feature coverage are unchanged.
This release uses only synthetic `.invalid` identities and mocked or isolated
providers. It does not claim that a real broker record was found or removed.
Real-world delivery and effectiveness remain deployment `needs_evidence` under
the authorized canary protocol.

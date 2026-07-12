const now = Date.now();

export const CONSENT_RECORDED_AT = new Date(now - 60_000).toISOString();
export const CONSENT_VALID_UNTIL = new Date(now + 364 * 24 * 60 * 60_000).toISOString();

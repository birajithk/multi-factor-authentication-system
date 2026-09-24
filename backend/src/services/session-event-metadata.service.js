/**
 * Build credential-free security-event metadata for the
 * TOTP login and session modules.
 *
 * Same shape as createPasswordSecurityEvent so Sathurshna's
 * common security logger can consume both the same way.
 *
 * This function does NOT persist the event, and callers must
 * never add TOTP codes, setup keys, or session tokens to it.
 */
export function createSessionSecurityEvent({
  eventType,
  outcome,
  correlationId,
  userId = null,
}) {
  return {
    eventType,
    timestamp: new Date().toISOString(),
    outcome,
    correlationId,
    userId,
  };
}

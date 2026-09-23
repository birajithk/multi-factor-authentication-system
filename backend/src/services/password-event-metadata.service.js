/**
 * Build credential-free security-event metadata for the
 * password authentication module.
 *
 * This function does NOT persist the event.
 * Sathurshna's common security logger will consume this object
 * during integration.
 */
export function createPasswordSecurityEvent({
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
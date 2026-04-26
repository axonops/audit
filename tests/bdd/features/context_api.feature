@core
Feature: Context-aware Audit API
  As a library consumer building services where audit calls share
  request lifecycles with HTTP handlers, background workers, or
  graceful shutdowns, I need an audit-emit method that accepts a
  context.Context — so cancellation, deadlines, and (eventually)
  trace correlation flow through the audit pipeline rather than
  being silently dropped at the library boundary.

  The Auditor.AuditEventContext API (#600) accepts ctx as the first
  parameter (Go stdlib idiom — slog.Handler.Handle(ctx, record),
  database/sql.QueryContext(ctx, ...)). The legacy AuditEvent(evt)
  remains as a context.Background() convenience wrapper. Cancellation
  is honoured at well-defined boundary points; Output.Write itself
  is not interruptible mid-call.

  Scenario: AuditEventContext with background context behaves like AuditEvent
    Given a standard test taxonomy
    And an auditor with stdout output
    When I call AuditEventContext with a background context for "user_create"
    Then the captured event field "actor_id" should equal "alice@example.com"

  Scenario: AuditEventContext returns ctx.Err when ctx cancelled before enqueue
    Given a standard test taxonomy
    And an auditor with stdout output
    When I call AuditEventContext with a pre-cancelled context for "user_create"
    Then the call should return context.Canceled
    And no event should be captured

  Scenario: AuditEventContext returns ctx.Err when deadline already exceeded
    Given a standard test taxonomy
    And an auditor with stdout output
    When I call AuditEventContext with a context whose deadline has expired for "user_create"
    Then the call should return context.DeadlineExceeded
    And no event should be captured

  Scenario: Diagnostic log distinguishes ctx-cancelled drops from buffer-full drops
    Given a standard test taxonomy
    And an auditor with a captured diagnostic logger
    When I call AuditEventContext with a pre-cancelled context for "user_create"
    Then the diagnostic log should record "event dropped due to context cancellation"
    And the diagnostic log should record the event_type "user_create"

  Scenario: EventHandle.AuditContext threads ctx through to delivery
    Given a standard test taxonomy
    And an auditor with stdout output
    And a registered EventHandle for "user_create"
    When I call EventHandle.AuditContext with a pre-cancelled context
    Then the call should return context.Canceled
    And no event should be captured

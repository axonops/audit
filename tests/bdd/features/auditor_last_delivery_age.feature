@core
Feature: Auditor.LastDeliveryAge per-output staleness signal
  As a library consumer building a /healthz liveness probe, I need
  the Auditor to expose the duration since each output's most recent
  successful delivery so that I can detect a silently-failing async
  output (TCP half-open, retries exhausted) whose Output.Write keeps
  enqueuing while no events ever land downstream.

  The contract for [audit.Auditor.LastDeliveryAge] (#753):

    1. Returns 0 (the "no-signal" sentinel) when:
       - the auditor is disabled;
       - the named output is not configured;
       - the named output does not implement LastDeliveryReporter
         (telemetry unavailable);
       - the named output has not yet completed a successful
         delivery.
       All four cases collapse to 0; callers disambiguate via
       OutputNames() and IsDisabled().

    2. Returns a strictly positive duration once a successful
       delivery has been recorded; the duration is computed against
       wall-clock time.now() at call time.

    3. The underlying LastDeliveryReporter timestamp ADVANCES on
       every successful delivery and STAYS FROZEN on every failure
       (write error, retries exhausted, server unreachable). A
       /healthz handler comparing age > threshold flips to 503 when
       deliveries actually stop.

    4. Forwarding through the namedOutput wrapper (used for
       YAML-named outputs) preserves the inner output's reporter
       semantics — wrapping is transparent.

  Background:
    Given a standard test taxonomy

  Scenario: Disabled auditor reports zero for any output name
    Given a disabled auditor
    When I read LastDeliveryAge for "anything"
    Then the reported delivery age should be the zero duration

  Scenario: Unknown output name reports zero
    Given an auditor with stdout output
    When I read LastDeliveryAge for "not-configured"
    Then the reported delivery age should be the zero duration

  Scenario: Output that has never delivered reports zero
    Given an auditor with stdout output
    When I read LastDeliveryAge for "stdout"
    Then the reported delivery age should be the zero duration

  Scenario: Successful synchronous delivery advances the staleness signal
    Given an auditor with stdout output
    When I audit event "user_create" with required fields
    And the auditor drains pending events
    Then LastDeliveryAge for "stdout" should be a positive duration under 5 seconds

  Scenario: Output without LastDeliveryReporter reports zero (no-signal)
    Given an auditor with a non-reporting mock output named "silent"
    When I read LastDeliveryAge for "silent"
    Then the reported delivery age should be the zero duration

  Scenario: namedOutput wrapper transparently forwards to the inner reporter
    Given an auditor with a YAML-named stdout output called "compliance"
    When I audit event "user_create" with required fields
    And the auditor drains pending events
    Then LastDeliveryAge for "compliance" should be a positive duration under 5 seconds

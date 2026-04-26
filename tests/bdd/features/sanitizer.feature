@core
Feature: Sanitizer interface for field and panic-value scrubbing
  As a library consumer concerned with privacy and compliance, I
  need a single hook that scrubs sensitive content out of audit
  event fields AND out of middleware-recovered panic values before
  they leave the auditor — so PII / secrets / internal error
  messages never reach the audit log or downstream panic handlers
  unsanitised.

  The Sanitizer interface (#598) has two methods: SanitizeField for
  per-field scrubbing on every Audit/AuditEvent call, and
  SanitizePanic for the middleware re-raise path. The interface is
  registered once via WithSanitizer; the same instance is consulted
  on every event.

  Scenario: Sanitizer scrubs a field value on every audit call
    Given a standard test taxonomy
    And an auditor with a Sanitizer that redacts the "actor_id" field
    When I audit a "user_create" event with actor_id "alice@example.com"
    Then the captured event field "actor_id" should equal "[redacted]"

  Scenario: Sanitizer with no configuration is a no-op
    Given a standard test taxonomy
    And an auditor with stdout output
    When I audit a "user_create" event with actor_id "alice@example.com"
    Then the captured event field "actor_id" should equal "alice@example.com"
    And the captured event should not have field "sanitizer_failed_fields"

  Scenario: SanitizeField panic produces sentinel and framework field
    Given a standard test taxonomy
    And an auditor with a Sanitizer that panics on "actor_id"
    When I audit a "user_create" event with actor_id "alice@example.com"
    Then the captured event field "actor_id" should equal "[sanitizer_panic]"
    And the captured event field "outcome" should equal "success"
    And the captured event "sanitizer_failed_fields" framework field should list "actor_id"

  Scenario: Diagnostic log never contains the raw field value when sanitiser panics
    Given a standard test taxonomy
    And an auditor with a Sanitizer that panics with the sentinel string captured
    When I audit a "user_create" event with actor_id "SECRET-PII-12345"
    Then the diagnostic log should record the SanitizeField panic
    And the diagnostic log should not contain "SECRET-PII-12345"

  Scenario: Sanitizer is invoked concurrently across many goroutines
    Given a standard test taxonomy
    And an auditor with a counting Sanitizer
    When 50 goroutines each emit 20 "user_create" events concurrently
    Then 1000 events should be captured
    And the Sanitizer should have been invoked at least 1000 times

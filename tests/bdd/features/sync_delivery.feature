@core @sync
Feature: Synchronous Delivery
  As a library consumer using WithSynchronousDelivery (or audittest's
  default mode), I want AuditEvent to deliver events to every output
  before returning so that test code can assert on outputs immediately
  with no Close-before-assert ceremony.

  Synchronous delivery is the default for the audittest helper package
  because it eliminates timing flakiness; it is also useful for CLI
  tools where the event count is small and async batching offers no
  benefit.

  Background:
    Given a standard test taxonomy

  Scenario: AuditEvent returns only after every output has received the event
    Given an auditor with synchronous delivery and two recording mock outputs
    When I audit event "user_create" with required fields
    Then both recording outputs should have received exactly 1 events

  Scenario: Synchronous delivery recovers a panicking output and returns no error
    Given an auditor with synchronous delivery, file output, and a panicking output
    When I audit a uniquely marked "user_create" event
    Then the audit call should return no error
    And the file should contain the marker

  Scenario: Synchronous delivery blocks the caller for the duration of every output Write
    Given an auditor with synchronous delivery and a slow output that blocks 50ms per write
    When I audit event "user_create" with required fields
    Then the audit call should return no error
    And the audit call should have taken at least 50 milliseconds

  Scenario: Synchronous Close is idempotent and AuditEvent after Close returns ErrClosed
    Given an auditor with synchronous delivery and a recording mock output
    When I close the auditor
    And I close the auditor again
    Then the second close should return no error
    When I try to audit event "user_create" with required fields
    Then the audit call should return an error wrapping "ErrClosed"
    And the recording output should have received exactly 0 events

  Scenario: audittest.NewQuick defaults to synchronous delivery with no Close ceremony
    Given an audittest auditor created via NewQuick with a standard taxonomy
    When I audit event "user_create" with required fields via the audittest auditor
    Then the audittest recorder should contain exactly 1 "user_create" event with no Close call

  Scenario: Synchronous delivery serialises concurrent AuditEvent calls without losses
    Given an auditor with synchronous delivery and a recording mock output
    When I audit 100 events from 10 concurrent goroutines
    Then the recording output should have received exactly 100 events

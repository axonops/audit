@core @shutdown
Feature: Graceful Shutdown
  As a library consumer, I want the auditor to drain all pending events
  when I call Close so that no audit data is lost during application
  shutdown.

  Background:
    Given a standard test taxonomy

  Scenario: Pending events are drained on close
    Given an auditor with file output at a temporary path
    When I audit 10 events rapidly
    And I close the auditor
    Then the file should contain exactly 10 events

  Scenario: Close is idempotent
    Given an auditor with file output at a temporary path
    When I audit event "user_create" with required fields
    And I close the auditor
    And I close the auditor again
    Then the second close should return no error

  Scenario: Audit after close returns ErrClosed
    Given an auditor with stdout output
    When I close the auditor
    And I try to audit event "user_create" with required fields
    Then the audit call should return an error wrapping "ErrClosed"

  Scenario: Close with zero outputs completes successfully
    Given an auditor with no outputs
    When I close the auditor
    Then the audit call should return no error

  Scenario: Multiple events all drained before close returns
    Given an auditor with file output at a temporary path
    When I audit 50 events rapidly
    And I close the auditor
    Then the file should contain exactly 50 events
    And every event in the file should be valid JSON

  Scenario: Drain timeout does not hang indefinitely
    Given an auditor with file output at a temporary path and short drain timeout
    When I audit 100 events rapidly
    Then closing the auditor should complete within 5 seconds

  Scenario: Concurrent close calls are safe
    Given an auditor with file output at a temporary path
    When I audit event "user_create" with required fields
    And I close the auditor from 5 goroutines concurrently
    Then no panic should have occurred

  @docker @syslog
  Scenario: Close with multiple outputs closes all
    Given an auditor with file and syslog outputs
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the file should contain the marker
    And the syslog server should contain the marker within 10 seconds

  @docker @syslog
  Scenario: Per-output async buffers drained during close
    Given an auditor with file and syslog outputs
    When I audit 10 uniquely marked events
    And I close the auditor
    Then the file should contain exactly 10 events
    And the syslog server should contain all 10 markers within 15 seconds

@core @shutdown
Feature: Graceful Shutdown
  As a library consumer, I want the logger to drain all pending events
  when I call Close so that no audit data is lost during application
  shutdown.

  Background:
    Given a standard test taxonomy

  Scenario: Pending events are drained on close
    Given a logger with file output at a temporary path
    When I audit 10 events rapidly
    And I close the logger
    Then the file should contain exactly 10 events

  Scenario: Close is idempotent
    Given a logger with file output at a temporary path
    When I audit event "user_create" with required fields
    And I close the logger
    And I close the logger again
    Then the second close should return no error

  Scenario: Audit after close returns ErrClosed
    Given a logger with stdout output
    When I close the logger
    And I try to audit event "user_create" with required fields
    Then the audit call should return an error wrapping "ErrClosed"

  Scenario: Close with zero outputs completes successfully
    Given a logger with no outputs
    When I close the logger
    Then the audit call should return no error

  Scenario: Multiple events all drained before close returns
    Given a logger with file output at a temporary path
    When I audit 50 events rapidly
    And I close the logger
    Then the file should contain exactly 50 events
    And every event in the file should be valid JSON

  Scenario: Drain timeout does not hang indefinitely
    Given a logger with file output at a temporary path and short drain timeout
    When I audit 100 events rapidly
    Then closing the logger should complete within 5 seconds

  Scenario: Concurrent close calls are safe
    Given a logger with file output at a temporary path
    When I audit event "user_create" with required fields
    And I close the logger from 5 goroutines concurrently
    Then no panic should have occurred

  Scenario: Close with multiple outputs closes all
    Given a logger with file and syslog outputs
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the file should contain the marker
    And the syslog server should contain the marker within 10 seconds

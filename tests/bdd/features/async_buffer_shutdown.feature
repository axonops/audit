@core @shutdown
Feature: Async Buffer Shutdown
  As a library consumer, I want Close to drain all per-output async
  buffers before returning so that no audit data is silently lost
  during application shutdown.

  Each async output (file, syslog, webhook, loki) has an internal
  buffered channel. Close signals the background writeLoop to drain
  remaining events, then waits for completion with a timeout.

  Background:
    Given a standard test taxonomy

  Scenario: File output drains all buffered events on close
    Given a logger with file output at a temporary path
    When I audit 50 events rapidly
    And I close the logger
    Then the file should contain exactly 50 events

  Scenario: Close with async file output is idempotent
    Given a logger with file output at a temporary path
    When I audit event "user_create" with required fields
    And I close the logger
    And I close the logger again
    Then the second close should return no error
    And the file should contain exactly 1 event

  Scenario: Concurrent close and audit does not panic
    Given a logger with file output at a temporary path
    When I audit event "user_create" with required fields
    And I close the logger from 5 goroutines concurrently
    Then no panic should have occurred

  Scenario: Close with error output does not block file drain
    Given a logger with file output and an error-returning output
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the file should contain the marker

  Scenario: Shutdown completes within timeout when output Write blocks
    Given a logger with a blocking output and drain timeout 1s
    When I audit event "user_create" with required fields
    Then closing the logger should complete within 5 seconds

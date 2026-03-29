@core @metrics
Feature: Metrics Interface
  As a library consumer, I want the logger to record metrics for all
  pipeline events so that I can monitor audit health via my observability
  stack.

  The core audit.Metrics interface records: event delivery (success/error),
  validation errors, filter drops, serialisation errors, and buffer drops.
  Output-specific metrics (file rotation, syslog reconnect, webhook flush)
  are tested in their respective output features.

  Background:
    Given a standard test taxonomy
    And mock metrics are configured

  Scenario: Successful event delivery records success metric
    Given a logger with stdout output and metrics
    When I audit event "user_create" with required fields
    And I close the logger
    Then the metrics should have recorded event "success" for output "stdout"

  Scenario: Validation error records validation metric
    Given a logger with stdout output and metrics
    When I audit event "nonexistent_event" with fields:
      | field   | value   |
      | outcome | success |
    Then the metrics should have recorded a validation error

  Scenario: Missing required field records validation metric
    Given a logger with stdout output and metrics
    When I audit event "user_create" with fields:
      | field   | value   |
      | outcome | success |
    Then the metrics should have recorded a validation error

  Scenario: Filtered event records filter metric
    Given a filtering taxonomy with only "write" enabled
    And a logger with stdout output and metrics
    When I audit event "auth_failure" with required fields
    Then the metrics should have recorded a filtered event "auth_failure"

  Scenario: Nil metrics does not cause panic
    Given a logger with stdout output
    When I audit event "user_create" with required fields
    And I close the logger
    Then the event should be delivered successfully

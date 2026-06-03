@core @metrics
Feature: Metrics Interface
  As a library consumer, I want the auditor to record metrics for all
  pipeline events so that I can monitor audit health via my observability
  stack.

  The core audit.Metrics interface records: pipeline-wide output write
  errors, validation errors, filter drops, serialisation errors, and
  core intake buffer drops. Per-output delivery counts (success and
  error event totals) come from OutputMetrics.RecordFlush and
  RecordError(count), tested in the output_metrics_factory feature and
  the per-output features (file/syslog/webhook/loki/splunk).

  Background:
    Given a standard test taxonomy
    And mock metrics are configured

  Scenario: Validation error records validation metric
    Given an auditor with stdout output and metrics
    When I audit event "nonexistent_event" with fields:
      | field   | value   |
      | outcome | success |
    Then the metrics should have recorded a validation error

  Scenario: Missing required field records validation metric
    Given an auditor with stdout output and metrics
    When I audit event "user_create" with fields:
      | field   | value   |
      | outcome | success |
    Then the metrics should have recorded a validation error

  Scenario: Filtered event records filter metric
    Given a standard test taxonomy
    And an auditor with stdout output and metrics
    And I disable category "security"
    When I audit event "auth_failure" with required fields
    Then the metrics should have recorded a filtered event "auth_failure"

  Scenario: Nil metrics does not cause panic
    Given an auditor with stdout output
    When I audit event "user_create" with required fields
    And I close the auditor
    Then the event should be delivered successfully

  Scenario: Unknown field in strict mode records validation error
    Given an auditor with stdout output and metrics in strict mode
    When I audit event "user_create" with required fields and an unknown field "extra"
    Then the metrics should have recorded a validation error

  Scenario: Unknown field in warn mode does not record validation error
    Given an auditor with stdout output and metrics in warn mode
    When I audit event "user_create" with required fields and an unknown field "extra"
    Then the metrics should not have recorded a validation error

  Scenario: Buffer drop metric recorded when buffer full
    Given an auditor with stdout output and metrics and buffer size 1
    When I fill the auditor buffer beyond capacity
    Then the metrics should have recorded at least 1 buffer drop

  Scenario: Per-output route filter records output filtered metric
    Given a routing taxonomy with write, read, and security categories
    And an auditor with routed outputs and metrics where webhook excludes "write"
    When I audit a "user_create" event in category "write" with marker "m_filt"
    And I close the auditor
    Then the metrics should have recorded an output filtered event

  Scenario: Nil metrics with validation error does not panic
    Given an auditor with stdout output
    When I audit event "nonexistent_event" with fields:
      | field   | value   |
      | outcome | success |
    Then the audit call should return an error matching:
      """
      audit: unknown event type "nonexistent_event"
      """

  Scenario: Serialization error records serialization metric
    Given mock metrics are configured
    And an auditor with error-returning formatter and metrics
    When I audit event "user_create" with required fields
    And I close the auditor
    Then the metrics should have recorded a serialization error

  Scenario: Output write failure records pipeline-wide output error
    Given mock metrics are configured
    And an auditor with error output and metrics
    When I audit event "user_create" with required fields
    And I close the auditor
    Then the metrics should have recorded an output error for "error-output"

  Scenario: Nil metrics with filtered event does not panic
    Given a standard test taxonomy
    And an auditor with stdout output
    And I disable category "security"
    When I audit event "auth_failure" with required fields
    Then the audit call should return no error

  # Notes (#894): the prior success/failure RecordDelivery scenarios
  # (lines 16-20, 49-53 in the v0.2.0 version of this feature) and
  # the "DeliveryReporter does not double-record" scenario (lines
  # 94-101) were removed when Metrics.RecordDelivery and
  # DeliveryReporter were deleted. Per-output delivery counts (success
  # AND error event totals) now flow through OutputMetrics.RecordFlush
  # (batchSize sum) and OutputMetrics.RecordError(count); the
  # output_metrics_factory.feature scenarios assert the new contract
  # end-to-end with mock OutputMetrics implementations.

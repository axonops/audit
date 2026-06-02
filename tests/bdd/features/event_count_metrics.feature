@core @metrics
Feature: Event Count Metrics
  As a library consumer, I want RecordSubmitted to count every event
  entering the pipeline so that I can track total inflow independently
  of delivery, filtering, and validation.

  The Metrics.RecordSubmitted method is called once per AuditEvent call,
  before any filtering, validation, or buffering. This is the "total
  events in" counter. Combined with the per-output RecordFlush sums
  (which carry the "delivered events" total) and drop counters,
  consumers can compute event accounting:
    submitted = delivered + filtered + dropped + validation_errors +
    serialization_errors.

  Background:
    Given a standard test taxonomy
    And mock metrics are configured

  Scenario: RecordSubmitted called for every AuditEvent
    Given an auditor with stdout output and metrics
    When I audit 10 events rapidly
    And I close the auditor
    Then RecordSubmitted should have been called 10 times

  Scenario: RecordSubmitted called even for filtered events
    Given an auditor with stdout output and metrics
    And I disable category "security"
    When I audit event "auth_failure" with required fields
    And I audit event "auth_failure" with required fields
    And I audit event "auth_failure" with required fields
    And I close the auditor
    Then RecordSubmitted should have been called 3 times

  Scenario: RecordSubmitted called for validation errors
    Given an auditor with stdout output and metrics
    When I audit event "nonexistent_event" with fields:
      | field   | value   |
      | outcome | success |
    And I close the auditor
    Then RecordSubmitted should have been called 1 time

  Scenario: RecordQueueDepth called from drain loop
    Given an auditor with stdout output and metrics
    When I audit 200 events rapidly
    And I close the auditor
    Then RecordQueueDepth should have been called at least 1 time

  # Notes (#894): the prior "DeliveryReporter skips core RecordDelivery"
  # + "non-DeliveryReporter records core RecordDelivery" scenarios were
  # removed when Metrics.RecordDelivery and DeliveryReporter were
  # deleted. Per-output delivery counts now flow exclusively through
  # OutputMetrics.RecordFlush — see the output_metrics_factory feature
  # for the RecordFlush-sum assertions, and the per-output features
  # (file/syslog/webhook/loki/splunk) for output-scoped coverage.

@core @metrics
Feature: Event Count Metrics
  As a library consumer, I want RecordSubmitted to count every event
  entering the pipeline so that I can track total inflow independently
  of delivery, filtering, and validation.

  The Metrics.RecordSubmitted method is called once per AuditEvent call,
  before any filtering, validation, or buffering. This is the "total
  events in" counter. Combined with delivery and drop counters, consumers
  can compute event accounting: submitted = delivered + filtered +
  dropped + validation_errors + serialization_errors.

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

  Scenario: DeliveryReporter output skips core RecordDelivery
    Given an auditor with file output and pipeline metrics
    When I audit 5 events rapidly
    And I close the auditor
    Then the pipeline metrics should not have recorded a success event for file output

  Scenario: Non-DeliveryReporter output records core RecordDelivery
    Given an auditor with stdout output and metrics
    When I audit event "user_create" with required fields
    And I close the auditor
    Then the metrics should have recorded event "success" for output "stdout"

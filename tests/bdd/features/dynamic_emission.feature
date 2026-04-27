@core @dynamic_emission
Feature: Dynamic Event Emission
  As a library consumer who has not generated typed builders, I want
  audit.NewEvent / NewEventKV to emit events from a runtime-supplied
  event type and Fields map, so I can use the library without running
  audit-gen and without committing generated code to my project.

  These scenarios cover the dynamic-API contract that complements the
  generated-builder path: same auditor, same outputs, same
  taxonomy-validation rules — only the event-construction path
  differs. Audit-gen generates typed builders against the same
  validation rules exercised here, so a regression on either side
  surfaces in this file or in typed_builders.feature.

  Background:
    Given a standard test taxonomy

  Scenario: NewEvent delivers event to output
    Given an auditor with stdout output
    When I audit via NewEvent "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the stdout output should contain event_type "user_create"
    And the stdout output should contain field "actor_id" with value "alice"

  Scenario: AuditEvent with nil event returns error
    Given an auditor with stdout output
    When I audit a nil event
    Then the last error should contain "event must not be nil"

  Scenario: NewEvent with missing required field returns error
    Given an auditor with stdout output
    When I audit via NewEvent "user_create" with fields:
      | field   | value   |
      | outcome | success |
    Then the last error should contain "missing required"

  Scenario: NewEvent with unknown event type returns error
    Given an auditor with stdout output
    When I audit via NewEvent "nonexistent_event" with fields:
      | field   | value   |
      | outcome | success |
    Then the last error should contain "unknown event type"

  Scenario: NewEvent with optional fields delivered correctly
    Given an auditor with stdout output
    When I audit via NewEvent "user_create" with fields:
      | field    | value       |
      | outcome  | success     |
      | actor_id | alice       |
      | marker   | test-marker |
    Then the stdout output should contain field "marker" with value "test-marker"

  Scenario: Multiple NewEvent calls deliver multiple events
    Given an auditor with stdout output
    When I audit via NewEvent "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I audit via NewEvent "auth_failure" with fields:
      | field    | value   |
      | outcome  | failure |
      | actor_id | unknown |
    Then the output should contain exactly 2 events

  Scenario: NewEvent delivers correct field values under drain pool recycling
    Given an auditor with stdout output
    When I audit via NewEvent "user_create" with fields:
      | field    | value    |
      | outcome  | success  |
      | actor_id | alice    |
      | marker   | event-a  |
    And I audit via NewEvent "user_create" with fields:
      | field    | value   |
      | outcome  | failure |
      | actor_id | bob     |
      | marker   | event-b |
    Then the output should contain exactly 2 events
    And the stdout output should contain field "marker" with value "event-a"
    And the stdout output should contain field "marker" with value "event-b"

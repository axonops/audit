@core
Feature: Core Audit Logging
  As a library consumer, I want to emit audit events through a configured
  logger so that security-relevant actions are recorded to my chosen outputs.

  The audit pipeline validates events against a YAML taxonomy, filters by
  category, serialises to JSON or CEF, and fans out to one or more outputs.
  Every event includes auto-populated timestamp and event_type fields.

  Background:
    Given a standard test taxonomy
    And a logger with stdout output

  # --- Happy paths with complete payload assertion ---

  Scenario: Emit a valid audit event with all required fields
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the event should be delivered successfully
    And the output should contain an event matching:
      | field       | value       |
      | event_type  | user_create |
      | outcome     | success     |
      | actor_id    | alice       |
      | marker      |             |
      | target_id   |             |
      | target_type |             |
      | reason      |             |
      | source_ip   |             |
      | user_agent  |             |
      | request_id  |             |
      | duration_ms |             |

  Scenario: Emit event with required and optional fields — complete payload
    When I audit event "user_create" with fields:
      | field     | value       |
      | outcome   | success     |
      | actor_id  | alice       |
      | marker    | bdd-test-1  |
      | target_id | user-42     |
    Then the event should be delivered successfully
    And the output should contain an event matching:
      | field       | value       |
      | event_type  | user_create |
      | outcome     | success     |
      | actor_id    | alice       |
      | marker      | bdd-test-1  |
      | target_id   | user-42     |
      | target_type |             |
      | reason      |             |
      | source_ip   |             |
      | user_agent  |             |
      | request_id  |             |
      | duration_ms |             |

  Scenario: Auto-populated fields are always present with correct values
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the event should be delivered successfully
    And the output should contain an event with event_type "user_create"
    And the output event timestamp should be a valid RFC3339 value

  # --- Error paths ---

  Scenario: Unknown event type returns error with exact message
    When I audit event "nonexistent_event" with fields:
      | field    | value   |
      | outcome  | success |
    Then the audit call should return an error matching:
      """
      audit: unknown event type "nonexistent_event"
      """

  Scenario: Missing a single required field returns exact error
    When I audit event "user_create" with fields:
      | field   | value   |
      | outcome | success |
    Then the audit call should return an error matching:
      """
      audit: event "user_create" missing required fields: [actor_id]
      """

  Scenario: Missing multiple required fields returns exact error
    When I audit event "user_create" with fields:
      | field  | value  |
      | marker | test-1 |
    Then the audit call should return an error matching:
      """
      audit: event "user_create" missing required fields: [actor_id, outcome]
      """

  Scenario: Audit after close returns ErrClosed
    Given I close the logger
    When I try to audit event "user_create" with required fields
    Then the audit call should return an error wrapping "ErrClosed"

  # --- Edge cases ---

  Scenario: Disabled logger discards events silently
    Given a disabled logger
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the audit call should return no error
    And no events should be delivered

  # --- Handle / MustHandle ---

  Scenario: Handle returns valid event type for registered event
    When I get a handle for event type "user_create"
    Then the handle should be valid
    And the handle name should be "user_create"

  Scenario: Handle returns error for unregistered event type
    When I try to get a handle for event type "nonexistent"
    Then the handle should return an error wrapping "ErrHandleNotFound"

  Scenario: Audit via handle delivers same event as Audit method
    When I get a handle for event type "user_create"
    And I audit via handle with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the output should contain an event matching:
      | field       | value       |
      | event_type  | user_create |
      | outcome     | success     |
      | actor_id    | alice       |
      | marker      |             |
      | target_id   |             |
      | target_type |             |
      | reason      |             |
      | source_ip   |             |
      | user_agent  |             |
      | request_id  |             |
      | duration_ms |             |

  # --- OmitEmpty ---

  Scenario: OmitEmpty true omits zero-value optional fields
    Given a logger with stdout output and OmitEmpty "true"
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the output should contain an event matching:
      | field      | value       |
      | event_type | user_create |
      | outcome    | success     |
      | actor_id   | alice       |

  Scenario: OmitEmpty false includes zero-value optional fields as null
    Given a logger with stdout output and OmitEmpty "false"
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the output should contain an event matching:
      | field       | value       |
      | event_type  | user_create |
      | outcome     | success     |
      | actor_id    | alice       |
      | marker      |             |
      | target_id   |             |
      | target_type |             |
      | reason      |             |
      | source_ip   |             |
      | user_agent  |             |
      | request_id  |             |
      | duration_ms |             |

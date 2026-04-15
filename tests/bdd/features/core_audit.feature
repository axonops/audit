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
      | duration_ms |             |

  Scenario: Auto-populated fields are always present with correct values
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the event should be delivered successfully
    And the output should contain an event with event_type "user_create"
    And the output event timestamp should be a valid RFC3339 value

  # --- Framework fields (#237) ---

  Scenario: Framework fields appear in JSON output
    Given framework fields app_name "myapp" host "prod-01" timezone "UTC"
    And a logger with stdout output
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the event should be delivered successfully
    And the output should contain field "app_name" with value "myapp"
    And the output should contain field "host" with value "prod-01"
    And the output should contain field "timezone" with value "UTC"
    And the output should contain field "pid" as a positive integer

  Scenario: PID is always present as a positive integer
    Given a logger with stdout output
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the event should be delivered successfully
    And the output should contain field "pid" as a positive integer

  Scenario: PID present even without app_name or host
    Given a logger with stdout output
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the event should be delivered successfully
    And the output should contain field "pid" as a positive integer
    And the output should not contain field "app_name"
    And the output should not contain field "host"

  Scenario: Timezone and PID auto-detected when not configured
    Given a logger with stdout output
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the event should be delivered successfully
    And the output should not contain field "app_name"
    And the output should not contain field "host"
    And the output should contain field "pid" as a positive integer

  Scenario: Framework fields present with OmitEmpty true
    Given framework fields app_name "myapp" host "prod-01" timezone "UTC"
    And a logger with stdout output and OmitEmpty "true"
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the event should be delivered successfully
    And the output should contain field "app_name" with value "myapp"
    And the output should contain field "host" with value "prod-01"
    And the output should contain field "pid" as a positive integer

  # --- Standard field defaults (#237) ---

  Scenario: Standard field default applied when event omits the field
    Given standard field defaults:
      | field     | value    |
      | source_ip | 10.0.0.1 |
    And a logger with stdout output
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the event should be delivered successfully
    And the output should contain field "source_ip" with value "10.0.0.1"

  Scenario: Per-event value overrides standard field default
    Given standard field defaults:
      | field     | value    |
      | source_ip | 10.0.0.1 |
    And a logger with stdout output
    When I audit event "user_create" with fields:
      | field     | value       |
      | outcome   | success     |
      | actor_id  | alice       |
      | source_ip | 192.168.1.1 |
    Then the event should be delivered successfully
    And the output should contain field "source_ip" with value "192.168.1.1"

  Scenario: Empty string per-event overrides standard field default
    Given standard field defaults:
      | field     | value    |
      | source_ip | 10.0.0.1 |
    And a logger with stdout output
    When I audit event "user_create" with fields:
      | field     | value   |
      | outcome   | success |
      | actor_id  | alice   |
      | source_ip |         |
    Then the event should be delivered successfully
    And the output should contain field "source_ip" with value ""

  Scenario: Multiple standard field defaults applied
    Given standard field defaults:
      | field     | value     |
      | source_ip | 10.0.0.1  |
      | reason    | scheduled |
    And a logger with stdout output
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the event should be delivered successfully
    And the output should contain field "source_ip" with value "10.0.0.1"
    And the output should contain field "reason" with value "scheduled"

  Scenario: Standard field default satisfies required true
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            source_ip: {required: true}
      """
    And standard field defaults:
      | field     | value    |
      | source_ip | 10.0.0.1 |
    And a logger with stdout output and validation mode "strict"
    When I audit event "user_create" with fields:
      | field   | value   |
      | outcome | success |
    Then the event should be delivered successfully
    And the output should contain field "source_ip" with value "10.0.0.1"

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

  # --- Nil/empty fields ---

  Scenario: Nil fields map accepted when event has no required fields
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        ops:
          - ping
      events:
        ping:
          fields: {}
      """
    And a logger with stdout output
    When I audit event "ping" with nil fields
    Then the event should be delivered successfully

  Scenario: Empty fields map with required fields returns error
    When I audit event "user_create" with empty fields
    Then the audit call should return an error matching:
      """
      audit: event "user_create" missing required fields: [actor_id, outcome]
      """

  # --- MustHandle ---

  Scenario: MustHandle returns valid handle for registered event
    When I must-handle event type "user_create"
    Then the handle should be valid
    And the handle name should be "user_create"

  Scenario: MustHandle panics for unregistered event type
    When I must-handle event type "nonexistent"
    Then the must-handle should have panicked

  # --- ErrQueueFull ---

  Scenario: Buffer full returns ErrQueueFull
    Given a logger with stdout output and buffer size 1
    When I fill the buffer and audit one more event
    Then the audit call should return an error wrapping "ErrQueueFull"

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
      | duration_ms |             |

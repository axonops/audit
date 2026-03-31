@core @multi-category
Feature: Multi-category event delivery and severity
  As a library consumer, I want events that belong to multiple taxonomy
  categories to be delivered once per enabled category, and I want each
  delivery to carry the correct taxonomy-resolved severity in its
  formatted output.

  Multi-category membership is a first-class taxonomy concept: an event
  may appear in "security" and "compliance" simultaneously, and each
  enabled category produces an independent delivery pass to all outputs
  whose route matches that category.

  Background:
    Given a multi-category taxonomy

  # ---------------------------------------------------------------------------
  # Multi-category delivery to an unrouted output
  # ---------------------------------------------------------------------------

  Scenario: Event in two enabled categories is delivered twice to unrouted output
    Given a logger with stdout output
    When I audit event "auth_failure" with fields:
      | field    | value   |
      | outcome  | failure |
      | actor_id | alice   |
    Then the output should contain exactly 2 events
    And all delivered events should have event_type "auth_failure"

  Scenario: Event in two categories with include route for one category delivers once
    Given a logger with stdout output routed to include only "security"
    When I audit event "auth_failure" with fields:
      | field    | value   |
      | outcome  | failure |
      | actor_id | alice   |
    Then the output should contain exactly 1 event
    And all delivered events should have event_type "auth_failure"

  Scenario: Event in two categories with exclude route for one category delivers once
    Given a logger with stdout output routed to exclude "compliance"
    When I audit event "auth_failure" with fields:
      | field    | value   |
      | outcome  | failure |
      | actor_id | alice   |
    Then the output should contain exactly 1 event
    And all delivered events should have event_type "auth_failure"

  Scenario: Uncategorised event delivered exactly once to unrouted output
    Given a logger with stdout output
    When I audit event "data_export" with fields:
      | field   | value   |
      | outcome | success |
    Then the output should contain exactly 1 event
    And all delivered events should have event_type "data_export"

  Scenario: Uncategorised event not delivered to category-routed include output
    Given a logger with stdout output routed to include only "security"
    When I audit event "data_export" with fields:
      | field   | value   |
      | outcome | success |
    Then the output should contain exactly 0 events

  Scenario: Uncategorised event delivered via event-type include route
    Given a logger with stdout output routed to include event type "data_export"
    When I audit event "data_export" with fields:
      | field   | value   |
      | outcome | success |
    Then the output should contain exactly 1 event
    And all delivered events should have event_type "data_export"

  # ---------------------------------------------------------------------------
  # Enable/Disable category interactions with multi-category events
  # ---------------------------------------------------------------------------

  Scenario: Disabling one of two categories reduces delivery count to 1
    Given a logger with stdout output
    And I disable category "compliance"
    When I audit event "auth_failure" with fields:
      | field    | value   |
      | outcome  | failure |
      | actor_id | alice   |
    Then the output should contain exactly 1 event
    And all delivered events should have event_type "auth_failure"

  Scenario: Disabling both categories produces 0 deliveries
    Given a logger with stdout output
    And I disable category "security"
    And I disable category "compliance"
    When I audit event "auth_failure" with fields:
      | field    | value   |
      | outcome  | failure |
      | actor_id | alice   |
    Then the output should contain exactly 0 events

  Scenario: DisableEvent overrides both enabled categories and delivers 0 times
    Given a logger with stdout output
    When I disable event "auth_failure"
    And I audit event "auth_failure" with fields:
      | field    | value   |
      | outcome  | failure |
      | actor_id | alice   |
    Then the output should contain exactly 0 events

  Scenario: EnableEvent overrides both disabled categories and delivers on all category passes
    Given a logger with stdout output
    And I disable category "security"
    And I disable category "compliance"
    When I enable event "auth_failure"
    And I audit event "auth_failure" with fields:
      | field    | value   |
      | outcome  | failure |
      | actor_id | alice   |
    Then the output should contain exactly 2 events
    And all delivered events should have event_type "auth_failure"

  Scenario: EnableEvent with one category enabled and one disabled delivers on all passes
    Given a logger with stdout output
    And I disable category "compliance"
    When I enable event "auth_failure"
    And I audit event "auth_failure" with fields:
      | field    | value   |
      | outcome  | failure |
      | actor_id | alice   |
    Then the output should contain exactly 2 events
    And all delivered events should have event_type "auth_failure"

  # ---------------------------------------------------------------------------
  # Severity in formatted output
  # ---------------------------------------------------------------------------

  Scenario: Category severity appears in JSON output for an event with no event-level severity
    Given a multi-category severity taxonomy
    And a logger with stdout output
    When I audit event "auth_failure" with fields:
      | field    | value   |
      | outcome  | failure |
      | actor_id | alice   |
    Then the output should contain exactly 2 events
    And all delivered events should have JSON field "severity" equal to 3

  Scenario: Event-level severity overrides category severity in JSON output
    Given a taxonomy where auth_failure has event severity 10 in category with severity 3
    And a logger with stdout output
    When I audit event "auth_failure" with fields:
      | field    | value   |
      | outcome  | failure |
      | actor_id | alice   |
    Then the output should contain exactly 1 event
    And all delivered events should have JSON field "severity" equal to 10

  Scenario: Default severity 5 emitted when no severity is set anywhere
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        ops:
          - ping
      events:
        ping:
          required: [outcome]
      default_enabled:
        - ops
      """
    And a logger with stdout output
    When I audit event "ping" with fields:
      | field   | value   |
      | outcome | success |
    Then the output should contain exactly 1 event
    And all delivered events should have JSON field "severity" equal to 5

  Scenario: Explicit severity 0 is distinct from absent severity
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        ops:
          severity: 0
          events: [audit_event]
      events:
        audit_event:
          required: [outcome]
      default_enabled:
        - ops
      """
    And a logger with stdout output
    When I audit event "audit_event" with fields:
      | field   | value   |
      | outcome | success |
    Then the output should contain exactly 1 event
    And all delivered events should have JSON field "severity" equal to 0

  Scenario: CEF header contains correct taxonomy severity
    Given a multi-category severity taxonomy
    And a logger with stdout output using CEF formatter
    When I audit event "auth_failure" with fields:
      | field    | value   |
      | outcome  | failure |
      | actor_id | alice   |
    Then the CEF output severity should be 3

  Scenario: Mixed category formats — list format and struct format with severity — parse correctly
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        ops:
          - auth_failure
        security:
          severity: 8
          events: [auth_failure]
      events:
        auth_failure:
          required: [outcome]
      default_enabled:
        - ops
        - security
      """
    And a logger with stdout output
    When I audit event "auth_failure" with fields:
      | field   | value   |
      | outcome | failure |
    Then the output should contain exactly 2 events
    And all delivered events should have JSON field "severity" equal to 8

  # ---------------------------------------------------------------------------
  # Edge cases
  # ---------------------------------------------------------------------------

  Scenario: Same event audited twice produces double deliveries
    Given a logger with stdout output
    When I audit event "auth_failure" with fields:
      | field    | value    |
      | outcome  | failure  |
      | actor_id | alice    |
    And I audit event "auth_failure" with fields:
      | field    | value    |
      | outcome  | failure  |
      | actor_id | bob      |
    Then the output should contain exactly 4 events
    And all delivered events should have event_type "auth_failure"

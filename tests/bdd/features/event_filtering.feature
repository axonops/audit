@core @filtering
Feature: Event Filtering
  As a library consumer, I want to enable and disable event categories
  at runtime so that I can control which events are recorded without
  restarting the application.

  Event filtering operates at two levels: category-level (enable/disable
  all events in a category) and per-event overrides (enable/disable a
  specific event type regardless of its category state). Per-event
  overrides always take precedence over category state.

  Background:
    Given a taxonomy with categories "write" and "security" where only "write" is enabled
    And a logger with stdout output

  # --- Category-level filtering ---

  Scenario: Events in enabled categories are delivered
    When I audit event "user_create" with required fields
    Then the event should be delivered successfully
    And the output should contain an event with event_type "user_create"

  Scenario: Events in disabled categories are silently discarded
    When I audit event "auth_failure" with required fields
    Then the audit call should return no error
    And no events should be delivered

  Scenario: Enabling a disabled category starts delivery
    Given I enable category "security"
    When I audit event "auth_failure" with required fields
    Then the event should be delivered successfully
    And the output should contain an event with event_type "auth_failure"

  Scenario: Disabling an enabled category stops delivery
    Given I disable category "write"
    When I audit event "user_create" with required fields
    Then the audit call should return no error
    And no events should be delivered

  Scenario: Empty DefaultEnabled disables all non-lifecycle events
    Given a taxonomy with all categories disabled by default
    And a logger with stdout output
    When I audit event "user_create" with required fields
    Then the audit call should return no error
    And no events should be delivered

  # --- Per-event overrides ---

  Scenario: EnableEvent overrides disabled category
    Given I enable event "auth_failure"
    When I audit event "auth_failure" with required fields
    Then the event should be delivered successfully

  Scenario: DisableEvent overrides enabled category
    Given I disable event "user_create"
    When I audit event "user_create" with required fields
    Then the audit call should return no error
    And no events should be delivered

  Scenario: Per-event override takes precedence over category state
    Given I disable category "write"
    And I enable event "user_create"
    When I audit event "user_create" with required fields
    Then the event should be delivered successfully

  # --- Error handling ---

  Scenario: Enabling unknown category returns error
    When I try to enable category "nonexistent"
    Then the operation should return an error containing "unknown"

  Scenario: Disabling unknown category returns error
    When I try to disable category "nonexistent"
    Then the operation should return an error containing "unknown"

  Scenario: Enabling unknown event type returns error
    When I try to enable event "nonexistent_event"
    Then the operation should return an error containing "unknown"

  Scenario: Disabling unknown event type returns error
    When I try to disable event "nonexistent_event"
    Then the operation should return an error containing "unknown"

@loki @docker
Feature: Loki Label Search and Filtering
  As a library consumer, I want to query audit events in Loki using
  stream labels so that I can find specific events efficiently without
  scanning every log line.

  Stream labels are the primary search mechanism in Loki. These tests
  push diverse events with different event types, severities, and
  categories, then query by specific labels to prove that ONLY matching
  events are returned — non-matching events MUST be excluded.

  Background:
    Given a standard test taxonomy

  # --- Search by event_type label ---

  Scenario: Query by event_type returns matching events and excludes others
    Given a logger with loki output with batch size 10
    When I audit a "user_create" event with marker "et_create"
    And I audit an "auth_failure" event with marker "et_auth"
    And I audit a "permission_denied" event with marker "et_perm"
    And I close the logger
    Then querying Loki by label "event_type" = "user_create" should return an event with:
      | field          | value          |
      | event_type     | user_create    |
      | outcome        | success        |
      | actor_id       | test-actor     |
      | app_name       | bdd-audit      |
      | host           | bdd-host       |
      | event_category | write          |
    And querying Loki by label "event_type" = "auth_failure" should return an event with:
      | field          | value          |
      | event_type     | auth_failure   |
      | outcome        | success        |
      | actor_id       | test-actor     |
      | app_name       | bdd-audit      |
      | host           | bdd-host       |
      | event_category | security       |
    And querying Loki by label "event_type" = "does_not_exist" should return no events within 3 seconds

  # --- Search by event_category label ---

  Scenario: Query by event_category returns matching events and excludes others
    Given a logger with loki output with batch size 10
    When I audit a "user_create" event with marker "cat_write"
    And I audit an "auth_failure" event with marker "cat_security"
    And I close the logger
    Then querying Loki by label "event_category" = "write" should return an event with:
      | field          | value          |
      | event_type     | user_create    |
      | outcome        | success        |
      | actor_id       | test-actor     |
      | app_name       | bdd-audit      |
      | host           | bdd-host       |
      | event_category | write          |
    And querying Loki by label "event_category" = "security" should return an event with:
      | field          | value          |
      | event_type     | auth_failure   |
      | outcome        | success        |
      | actor_id       | test-actor     |
      | app_name       | bdd-audit      |
      | host           | bdd-host       |
      | event_category | security       |
    And querying Loki by label "event_category" = "nonexistent" should return no events within 3 seconds

  # --- Search by app_name label ---

  Scenario: Query by app_name returns matching events and excludes others
    Given a logger with loki output
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And querying Loki by label "app_name" = "bdd-audit" should return the marker event within 15 seconds
    And querying Loki by label "app_name" = "other-app" should return no events within 3 seconds

  # --- Search by host label ---

  Scenario: Query by host returns matching events and excludes others
    Given a logger with loki output
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And querying Loki by label "host" = "bdd-host" should return the marker event within 15 seconds
    And querying Loki by label "host" = "wrong-host" should return no events within 3 seconds

  # --- Search by static label ---

  Scenario: Query by static label returns matching events and excludes others
    Given a logger with loki output with static label "environment" = "label_test"
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And querying Loki by label "environment" = "label_test" should return the marker event within 15 seconds
    And querying Loki by label "environment" = "production" should return no events within 3 seconds

  # --- Negative: nonexistent label values return nothing ---

  Scenario: Query by nonexistent event_type returns no events
    Given a logger with loki output
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And querying Loki by label "event_type" = "does_not_exist" should return no events within 3 seconds

  # --- Excluded label is not searchable ---

  Scenario: Excluded dynamic label cannot be used as search criterion
    Given a logger with loki output excluding dynamic label "severity"
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki stream should not have label "severity"
    And querying Loki by label "event_type" = "user_create" should return the marker event within 15 seconds

  # --- Combined label query with payload ---

  Scenario: Combined label and payload verification
    Given a logger with loki output with batch size 10
    When I audit a "user_create" event with marker "combo_create"
    And I audit an "auth_failure" event with marker "combo_auth"
    And I close the logger
    Then querying Loki by label "event_type" = "user_create" should return an event with:
      | field          | value          |
      | event_type     | user_create    |
      | outcome        | success        |
      | actor_id       | test-actor     |
      | event_category | write          |
      | app_name       | bdd-audit      |
      | host           | bdd-host       |
    And querying Loki by label "event_type" = "auth_failure" should return an event with:
      | field          | value          |
      | event_type     | auth_failure   |
      | outcome        | success        |
      | actor_id       | test-actor     |
      | event_category | security       |
      | app_name       | bdd-audit      |
      | host           | bdd-host       |

  Scenario: Timezone present in Loki event payload
    Given a logger with loki output with batch size 10
    When I audit a "user_create" event with marker "tz_payload"
    And I close the logger
    Then the loki server should contain the named marker "tz_payload" within 15 seconds
    And the loki event payload should contain field "timezone"

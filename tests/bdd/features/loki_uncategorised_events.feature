@loki @docker
Feature: Loki streams for uncategorised events
  As a library consumer, I want to understand how uncategorised events
  land in Loki so that I can write correct LogQL queries to find them.

  In Loki, stream labels partition events into separate log streams. The
  `event_category` label is derived from the taxonomy category an event
  belongs to. Events that are defined in the taxonomy but NOT placed in
  any category are "uncategorised" — they are delivered once with no
  category context. Their Loki stream has NO `event_category` label, and
  their JSON log line contains NO `event_category` field.

  This has two practical consequences:
    1. A query like `{event_category="write"}` will NOT return uncategorised
       events — they are in a different stream entirely.
    2. To find uncategorised events you must either omit the `event_category`
       selector (scanning all streams) or use LogQL negation to exclude
       the known categories.

  All events — categorised and uncategorised — are reachable via LogQL
  line filters that scan log line content, such as `|= "actor_id_value"`
  or `| json | actor_id="alice"`. The stream label is the partition
  mechanism; it is not a gate on queryability.

  The taxonomy used in this file is embedded as YAML. The `health_check`
  event is defined under `events:` but absent from every category — this
  is the minimal configuration to produce an uncategorised event.

  Background:
    Given a taxonomy from YAML:
      """
      version: 1

      categories:
        write:
          - user_create
        security:
          - auth_failure

      events:
        user_create:
          fields:
            outcome: {required: true}
            actor_id: {required: true}
            marker: {}

        auth_failure:
          fields:
            outcome: {required: true}
            actor_id: {required: true}
            marker: {}

        health_check:
          fields:
            outcome: {required: true}
            actor_id: {required: true}
            marker: {}
      """

  # ---------------------------------------------------------------------------
  # Categorised events carry the event_category label — baseline for contrast
  # ---------------------------------------------------------------------------

  Scenario: Categorised events carry event_category in both stream label and JSON payload
    Given an auditor with loki output with batch size 10
    When I audit a "user_create" event with marker "cat_write"
    And I audit an "auth_failure" event with marker "cat_sec"
    And I close the auditor
    Then querying Loki by label "event_category" = "write" should return an event with:
      | field          | value       |
      | event_type     | user_create |
      | outcome        | success     |
      | actor_id       | test-actor  |
      | event_category | write       |
      | app_name       | bdd-audit   |
      | host           | bdd-host    |
    And querying Loki by label "event_category" = "security" should return an event with:
      | field          | value        |
      | event_type     | auth_failure |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | event_category | security     |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |

  # ---------------------------------------------------------------------------
  # Uncategorised events land in a stream with no event_category label
  # ---------------------------------------------------------------------------

  Scenario: Uncategorised event stream has no event_category label
    # The health_check event is in the taxonomy but belongs to no category.
    # Its Loki stream must not carry the event_category label — querying by
    # {event_category="anything"} will never find it.
    Given an auditor with loki output
    When I audit a uniquely marked "health_check" event
    Then the loki server should contain the marker within 15 seconds
    And the loki stream should not have label "event_category"

  Scenario: Uncategorised event JSON payload contains no event_category field
    # The JSON log line for health_check must not include the event_category
    # key. The framework only appends event_category when the event has a
    # non-empty category — uncategorised events have none.
    Given an auditor with loki output
    When I audit a uniquely marked "health_check" event
    Then the loki server should contain the marker within 15 seconds
    And the loki event payload for the marker should not contain field "event_category"

  Scenario: Querying by event_category label does not return uncategorised events
    # Push one categorised and one uncategorised event with distinct markers.
    # The category label selector must find only its own event — proving the
    # streams are genuinely separate.
    Given an auditor with loki output with batch size 10
    When I audit a "user_create" event with marker "mixed_write"
    And I audit a "health_check" event with marker "mixed_uncat"
    And I close the auditor
    Then the loki server should contain the named marker "mixed_write" within 15 seconds
    And the loki server should contain the named marker "mixed_uncat" within 15 seconds
    And querying Loki by label "event_category" = "write" should not return named marker "mixed_uncat" within 3 seconds

  # ---------------------------------------------------------------------------
  # All events remain queryable across streams via content filters
  # ---------------------------------------------------------------------------

  Scenario: A shared actor_id field finds events across categorised and uncategorised streams
    # Both user_create (write category) and health_check (uncategorised)
    # carry actor_id in their JSON payload. A LogQL JSON filter searching
    # by actor_id must find both, proving uncategorised events are not lost.
    Given an auditor with loki output with batch size 10
    When I audit a "user_create" event with marker "actor_write"
    And I audit a "health_check" event with marker "actor_uncat"
    And I close the auditor
    Then the loki server should contain the named marker "actor_write" within 15 seconds
    And the loki server should contain the named marker "actor_uncat" within 15 seconds

  Scenario: A line filter finds all three events regardless of stream membership
    # Emit one event per category and one uncategorised. A line filter
    # that matches the shared test suite label finds all three — proving
    # event_category does not gate queryability.
    Given an auditor with loki output with batch size 10
    When I audit a "user_create" event with marker "all_write"
    And I audit an "auth_failure" event with marker "all_sec"
    And I audit a "health_check" event with marker "all_uncat"
    And I close the auditor
    Then the loki server should contain the named marker "all_write" within 15 seconds
    And the loki server should contain the named marker "all_sec" within 15 seconds
    And the loki server should contain the named marker "all_uncat" within 15 seconds

  # ---------------------------------------------------------------------------
  # LogQL negation isolates uncategorised events from categorised ones
  # ---------------------------------------------------------------------------

  Scenario: Negating all known categories finds only uncategorised events
    # A LogQL selector that excludes all known event_category values will
    # match only streams that have no event_category label — i.e., only
    # uncategorised events. This is the correct pattern for "show me
    # everything that has not been classified yet."
    Given an auditor with loki output with batch size 10
    When I audit a "user_create" event with marker "neg_write"
    And I audit an "auth_failure" event with marker "neg_sec"
    And I audit a "health_check" event with marker "neg_uncat"
    And I close the auditor
    Then querying Loki excluding event_category labels "write,security" should return the named marker "neg_uncat" within 15 seconds
    And querying Loki excluding event_category labels "write,security" should not return the named marker "neg_write" within 3 seconds
    And querying Loki excluding event_category labels "write,security" should not return the named marker "neg_sec" within 3 seconds

  # ---------------------------------------------------------------------------
  # Complete payload contract for uncategorised events
  # ---------------------------------------------------------------------------

  Scenario: Uncategorised event payload is complete apart from the absent event_category field
    # Verify every field that SHOULD be present, then explicitly verify
    # that event_category is absent. This documents the full contract.
    Given an auditor with loki output
    When I audit a uniquely marked "health_check" event
    Then the loki server should contain the marker within 15 seconds
    And the loki event payload should contain:
      | field      | value        |
      | event_type | health_check |
      | outcome    | success      |
      | actor_id   | test-actor   |
      | app_name   | bdd-audit    |
      | host       | bdd-host     |
    And the loki event payload for the marker should not contain field "event_category"

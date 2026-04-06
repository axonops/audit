@loki @docker @fanout
Feature: Multi-Output Fan-Out with Loki
  As a library consumer, I want to send audit events to Loki alongside
  file, syslog, and webhook outputs simultaneously so that I have
  redundant audit storage with diverse delivery channels.

  Loki uses WriteWithMetadata (async internal batching), while file,
  syslog, and webhook use synchronous Write. These tests verify that
  the async/sync mix works correctly in the fan-out pipeline.

  Background:
    Given the following taxonomy:
      """
      version: 1
      categories:
        security:
          - auth_login
          - auth_failure
        write:
          - user_create
      events:
        auth_login:
          fields:
            outcome: {required: true}
            actor_id: {required: true}
        auth_failure:
          severity: 8
          fields:
            outcome: {required: true}
            actor_id: {required: true}
            reason: {required: true}
        user_create:
          fields:
            outcome: {required: true}
            actor_id: {required: true}
      """

  Scenario: Event delivered to file and Loki simultaneously
    Given a logger with file and loki outputs
    When I audit a uniquely marked "user_create" event with actor "alice" and outcome "success"
    And I close the logger
    Then the loki server should contain the marker within 10 seconds
    And the file should contain the marker
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | alice        |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: Different routes per output with Loki receiving only security
    Given a logger with file receiving all events and loki receiving only "security"
    When I audit a uniquely marked "user_create" event with actor "alice" and outcome "success"
    And I audit a uniquely marked "auth_failure" event with actor "mallory" and outcome "failure" and field "reason" = "invalid_password"
    And I close the logger
    Then the file should contain both markers
    And querying Loki by label event_type = "auth_failure" should return the security marker within 10 seconds
    And querying Loki by label event_type = "user_create" should return no events within 5 seconds

  Scenario: HMAC present on both file and Loki with same salt
    Given a logger with file and loki outputs both HMAC-enabled with salt "fanout-hmac-salt-16!" version "v1"
    When I audit a uniquely marked "user_create" event with actor "alice" and outcome "success"
    And I close the logger
    Then the loki server should contain the marker within 10 seconds
    And the file should contain the marker
    And the file event should contain "_hmac" field
    And the loki event payload should contain field "_hmac"
    And the file and Loki "_hmac" values should match for the same event

  Scenario: PII stripped from Loki but preserved in file
    Given the following taxonomy:
      """
      version: 1
      categories:
        write:
          - user_create
      sensitivity:
        labels:
          pii:
            description: "Personally identifiable information"
            fields: [email]
      events:
        user_create:
          fields:
            outcome: {required: true}
            actor_id: {required: true}
            email:
              labels: [pii]
      """
    And a logger with file output keeping all fields and loki output excluding label "pii"
    When I audit a uniquely marked "user_create" event with actor "alice" and outcome "success" and field "email" = "alice@example.com"
    And I close the logger
    Then the loki server should contain the marker within 10 seconds
    And the file should contain "alice@example.com"
    And the loki event payload should not contain field "email"
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | alice        |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: Loki failure does not block file delivery
    Given a logger with file output and loki output to unreachable server
    When I audit a uniquely marked "user_create" event with actor "alice" and outcome "success"
    And I close the logger
    Then the file should contain the marker

  Scenario: Complete payload present in both file and Loki
    Given a logger with file and loki outputs
    When I audit a uniquely marked "user_create" event with actor "alice" and outcome "success"
    And I close the logger
    Then the loki server should contain the marker within 10 seconds
    And the file should contain the marker
    And the file event should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | alice        |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | alice        |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: Multiple events delivered to file and Loki
    Given a logger with file and loki outputs
    When I audit 3 uniquely marked "user_create" events with actor "alice" and outcome "success"
    And I close the logger
    Then the loki server should have at least 3 events within 10 seconds
    And the file should contain all 3 markers

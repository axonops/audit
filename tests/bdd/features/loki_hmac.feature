@loki @docker @hmac
Feature: HMAC Integrity with Loki Output
  As a library consumer using Loki for audit storage, I want HMAC
  integrity verification on events stored in Loki so that I can
  detect tampering by querying the event from Loki and independently
  verifying the HMAC.

  The HMAC is computed in the core pipeline over the serialised
  payload (after field stripping, after event_category append, before
  _hmac/_hmac_v append). The complete event including HMAC fields is
  then delivered to Loki via WriteWithMetadata. These tests verify
  the end-to-end chain: audit call → HMAC computation → Loki
  delivery → Loki query → independent HMAC verification.

  Background:
    Given the following taxonomy:
      """
      version: 1
      categories:
        security:
          - auth_login
        write:
          - user_create
      events:
        auth_login:
          fields:
            outcome: {required: true}
            actor_id: {required: true}
            marker: {}
        user_create:
          fields:
            outcome: {required: true}
            actor_id: {required: true}
            marker: {}
      """

  Scenario: HMAC fields present on event stored in Loki
    Given a logger with loki output and HMAC enabled using salt "loki-hmac-salt-16b!" version "v1" and hash "HMAC-SHA-256"
    When I audit a uniquely marked "user_create" event with actor "alice" and outcome "success"
    And I close the logger
    Then the loki server should contain the marker within 10 seconds
    And the loki event payload should contain field "_hmac"
    And the loki event payload should contain field "_hmac_v" with value "v1"
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | alice        |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: HMAC fields absent when HMAC not configured on Loki output
    Given a logger with loki output
    When I audit a uniquely marked "user_create" event with actor "alice" and outcome "success"
    And I close the logger
    Then the loki server should contain the marker within 10 seconds
    And the loki event payload should not contain field "_hmac"
    And the loki event payload should not contain field "_hmac_v"

  Scenario: HMAC stored in Loki is independently verifiable
    Given a logger with loki output and HMAC enabled using salt "loki-verify-salt-16!" version "v1" and hash "HMAC-SHA-256"
    When I audit a uniquely marked "user_create" event with actor "alice" and outcome "success"
    And I close the logger
    Then the loki server should contain the marker within 10 seconds
    And independently recomputing HMAC-SHA-256 over the loki payload with salt "loki-verify-salt-16!" matches the "_hmac" value

  Scenario: Different HMAC salts produce different HMACs on same event
    Given a logger with loki output using HMAC salt "loki-salt-alpha-16!" version "v1"
    And a capture output with HMAC salt "capture-salt-beta16!" version "v2"
    When I audit a uniquely marked "user_create" event with actor "alice" and outcome "success"
    And I close the logger
    Then the loki server should contain the marker within 10 seconds
    And the capture output should contain the marker
    And the HMAC in Loki should differ from the HMAC in the capture output

  Scenario: Salt version stored in Loki event
    Given a logger with loki output and HMAC enabled using salt "loki-version-salt-16" version "2026-Q2" and hash "HMAC-SHA-256"
    When I audit a uniquely marked "user_create" event with actor "alice" and outcome "success"
    And I close the logger
    Then the loki server should contain the marker within 10 seconds
    And the loki event payload should contain field "_hmac_v" with value "2026-Q2"

  Scenario: Sensitivity label stripping changes HMAC between Loki and full output
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
            marker: {}
            email:
              labels: [pii]
      """
    And a logger with loki output excluding label "pii" with HMAC salt "loki-strip-salt-16b!" version "v1"
    And a capture output with no exclusions and HMAC salt "capture-full-salt-16" version "v2"
    When I audit a uniquely marked "user_create" event with actor "alice" and outcome "success" and field "email" = "alice@example.com"
    And I close the logger
    Then the loki server should contain the marker within 10 seconds
    And the loki event payload should not contain field "email"
    And the capture output event should contain field "email" with value "alice@example.com"
    And both outputs should have "_hmac" fields
    And the HMAC values should differ between Loki and the capture output

  Scenario: Complete payload preserved alongside HMAC fields in Loki
    Given a logger with loki output and HMAC enabled using salt "loki-full-salt-16by!" version "v1" and hash "HMAC-SHA-256"
    When I audit a uniquely marked "user_create" event with actor "alice" and outcome "success"
    And I close the logger
    Then the loki server should contain the marker within 10 seconds
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | severity       | 5            |
      | outcome        | success      |
      | actor_id       | alice        |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |
    And the loki event payload should contain field "_hmac"
    And the loki event payload should contain field "_hmac_v" with value "v1"

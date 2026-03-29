@fanout @docker
Feature: Multi-Output Fan-Out
  As a library consumer, I want to send audit events to multiple outputs
  simultaneously so that I have redundant storage and diverse delivery
  channels.

  Background:
    Given a standard test taxonomy

  # --- Delivery ---

  Scenario: Event delivered to file and webhook simultaneously
    Given a logger with file and webhook outputs
    When I audit a uniquely marked "user_create" event
    Then the webhook receiver should have at least 1 event within 5 seconds
    And I close the logger
    And the file should contain the marker

  Scenario: Event delivered to file and syslog simultaneously
    Given a logger with file and syslog outputs
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the file should contain the marker
    And the syslog server should contain the marker within 10 seconds

  Scenario: Event delivered to all three outputs simultaneously
    Given a logger with file, syslog, and webhook outputs
    When I audit a uniquely marked "user_create" event
    Then the webhook receiver should have at least 1 event within 5 seconds
    And I close the logger
    And the file should contain the marker
    And the syslog server should contain the marker within 10 seconds

  # --- Failure isolation ---

  Scenario: Webhook failure does not block file delivery
    Given the webhook receiver is configured to return status 503
    And a logger with file and webhook outputs
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the file should contain the marker

  # --- Formatters ---

  Scenario: Mixed formatters per output
    Given a logger with file output using JSON and webhook output using CEF
    When I audit a uniquely marked "user_create" event
    Then the webhook receiver should have at least 1 event within 5 seconds
    And I close the logger
    And the file should contain JSON format with "event_type"

  # --- Construction validation ---

  Scenario: Duplicate output name rejected
    When I try to create a logger with duplicate output names
    Then the logger construction should fail with an error containing "duplicate"

  Scenario: Duplicate file destination rejected
    When I try to create a logger with two file outputs to the same path
    Then the logger construction should fail with an error containing "duplicate"

  # --- Complete payload ---

  Scenario: All fields present in both file and webhook output
    Given a logger with file and webhook outputs configured for batch size 1
    When I audit event "user_create" with fields:
      | field     | value       |
      | outcome   | success     |
      | actor_id  | alice       |
      | marker    | fanout_all  |
      | target_id | user-42     |
    Then the webhook receiver should have at least 1 event within 5 seconds
    And I close the logger
    And the file should contain an event matching:
      | field      | value       |
      | event_type | user_create |
      | outcome    | success     |
      | actor_id   | alice       |
      | marker     | fanout_all  |
      | target_id  | user-42     |
    And the webhook event body should contain field "event_type" with value "user_create"
    And the webhook event body should contain field "marker" with value "fanout_all"

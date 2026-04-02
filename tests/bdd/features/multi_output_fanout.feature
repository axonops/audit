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

  Scenario: Multiple events delivered to all outputs
    Given a logger with file and webhook outputs
    When I audit a "user_create" event in category "write" with marker "multi_all_1"
    And I audit a "user_create" event in category "write" with marker "multi_all_2"
    And I audit a "user_create" event in category "write" with marker "multi_all_3"
    Then the webhook receiver should have at least 3 events within 5 seconds
    And I close the logger
    And the file should contain "multi_all_1"
    And the file should contain "multi_all_2"
    And the file should contain "multi_all_3"

  # --- Failure isolation ---

  Scenario: Webhook failure does not block file delivery
    Given the webhook receiver is configured to return status 503
    And a logger with file and webhook outputs
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the file should contain the marker

  # --- Formatters ---

  Scenario: Shared formatter delivers identical content to both outputs
    Given a logger with two file outputs sharing the same formatter
    When I audit a "user_create" event in category "write" with marker "shared_fmt"
    And I close the logger
    Then both files should contain identical content

  Scenario: Mixed formatters per output
    Given a logger with file output using JSON and webhook output using CEF
    When I audit a uniquely marked "user_create" event
    Then the webhook receiver should have at least 1 event within 5 seconds
    And I close the logger
    And the file should contain JSON format with "event_type"

  # --- Construction validation ---

  Scenario: Duplicate output name rejected
    When I try to create a logger with duplicate output names
    Then the logger construction should fail with an error containing "duplicate output name"

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
      | field       | value       |
      | event_type  | user_create |
      | outcome     | success     |
      | actor_id    | alice       |
      | marker      | fanout_all  |
      | target_id   | user-42     |
      | duration_ms |             |
    And the webhook event body should contain field "event_type" with value "user_create"
    And the webhook event body should contain field "outcome" with value "success"
    And the webhook event body should contain field "actor_id" with value "alice"
    And the webhook event body should contain field "marker" with value "fanout_all"
    And the webhook event body should contain field "target_id" with value "user-42"
    And the webhook event body should contain field "timestamp"

  Scenario: Duplicate syslog destination rejected
    When I try to create a logger with two syslog outputs to the same address
    Then the logger construction should fail with an error containing "duplicate"

  # --- Panic recovery ---

  Scenario: Output write error logged but other outputs continue
    Given a logger with file output and an error-returning output
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the file should contain the marker

  Scenario: Panic in per-output formatter does not crash logger
    Given a logger with file output and a panicking formatter on a second output
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the file should contain the marker

  Scenario: Panic in output Write does not crash logger
    Given a logger with file output and a panicking output
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the file should contain the marker

  # --- Routing diversity ---

  Scenario: Different events routed to different file outputs
    Given a logger with two file outputs where security goes to file-a and write goes to file-b
    When I audit a "user_create" event in category "write" with marker "div_w"
    And I audit an "auth_failure" event in category "security" with marker "div_s"
    And I close the logger
    Then file "security" should contain "div_s"
    And file "security" should not contain "div_w"
    And file "write" should contain "div_w"
    And file "write" should not contain "div_s"

  Scenario: Three outputs with different routes verify distribution
    Given a logger with file getting all, syslog getting security, and webhook getting write
    When I audit a "user_create" event in category "write" with marker "dist_w"
    And I audit an "auth_failure" event in category "security" with marker "dist_s"
    Then the webhook receiver should have at least 1 event within 5 seconds
    And I close the logger
    And the file should contain "dist_w"
    And the file should contain "dist_s"
    And the syslog server should contain "dist_s" within 10 seconds

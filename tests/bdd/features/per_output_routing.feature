@routing @docker
Feature: Per-Output Event Routing
  As a library consumer, I want to route specific event categories to
  specific outputs so that high-security events go to a dedicated SIEM
  while operational events go to local files.

  This feature uses a routing taxonomy with write, read, and security
  categories to demonstrate real-world routing patterns.

  Background:
    Given a routing taxonomy with write, read, and security categories

  # --- Include mode ---

  Scenario: Include categories restricts output to matching events
    Given a logger with file receiving all events and webhook receiving only "security"
    When I audit a "user_create" event in category "write" with marker "route_inc_w"
    And I audit an "auth_failure" event in category "security" with marker "route_inc_s"
    Then the webhook receiver should have at least 1 event within 5 seconds
    And I close the logger
    And the file should contain "route_inc_w"
    And the file should contain "route_inc_s"
    And the webhook event body should contain field "event_type" with value "auth_failure"

  Scenario: Include event types restricts output to specific events
    Given a logger with file receiving all events and webhook including event types "auth_failure"
    When I audit a "user_create" event in category "write" with marker "route_evt_w"
    And I audit an "auth_failure" event in category "security" with marker "route_evt_s"
    Then the webhook receiver should have at least 1 event within 5 seconds
    And I close the logger
    And the file should contain "route_evt_w"
    And the file should contain "route_evt_s"

  # --- Exclude mode ---

  Scenario: Exclude categories removes matching events from output
    Given a logger with file receiving all events and webhook excluding categories "write"
    When I audit a "user_create" event in category "write" with marker "route_exc_w"
    And I audit an "auth_failure" event in category "security" with marker "route_exc_s"
    Then the webhook receiver should have at least 1 event within 5 seconds
    And I close the logger
    And the file should contain "route_exc_w"
    And the file should contain "route_exc_s"

  # --- Validation ---

  Scenario: Mixed include and exclude on same route is rejected
    When I try to create a logger with mixed include and exclude route
    Then the logger construction should fail with an error containing "include or exclude"

  Scenario: Route referencing unknown category is rejected
    When I try to create a logger with route referencing unknown category
    Then the logger construction should fail with an error

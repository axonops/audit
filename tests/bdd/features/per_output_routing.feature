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
    And the webhook should not contain event_type "user_create"

  Scenario: Include event types restricts output to specific events
    Given a logger with file receiving all events and webhook including event types "auth_failure"
    When I audit a "user_create" event in category "write" with marker "route_evt_w"
    And I audit an "auth_failure" event in category "security" with marker "route_evt_s"
    Then the webhook receiver should have at least 1 event within 5 seconds
    And I close the logger
    And the file should contain "route_evt_w"
    And the file should contain "route_evt_s"

  Scenario: Include multiple event types delivers union
    Given a logger with file receiving all events and webhook including event types "auth_failure,permission_denied"
    When I audit a "user_create" event in category "write" with marker "multi_evt_w"
    And I audit an "auth_failure" event in category "security" with marker "multi_evt_af"
    And I audit a "permission_denied" event in category "security" with marker "multi_evt_pd"
    Then the webhook receiver should have at least 2 events within 5 seconds
    And I close the logger
    And the file should contain "multi_evt_w"
    And the file should contain "multi_evt_af"
    And the file should contain "multi_evt_pd"

  # --- Exclude mode ---

  Scenario: Exclude categories removes matching events from output
    Given a logger with file receiving all events and webhook excluding categories "write"
    When I audit a "user_create" event in category "write" with marker "route_exc_w"
    And I audit an "auth_failure" event in category "security" with marker "route_exc_s"
    Then the webhook receiver should have at least 1 event within 5 seconds
    And I close the logger
    And the file should contain "route_exc_w"
    And the file should contain "route_exc_s"
    And the webhook should not contain event_type "user_create"

  # --- Validation ---

  Scenario: Mixed include and exclude on same route is rejected
    When I try to create a logger with mixed include and exclude route
    Then the logger construction should fail with an error containing "EventRoute must use either include or exclude, not both"

  Scenario: Route referencing unknown category is rejected
    When I try to create a logger with route referencing unknown category
    Then the logger construction should fail with an error

  Scenario: Route referencing unknown event type is rejected
    When I try to create a logger with route referencing unknown event type
    Then the logger construction should fail with an error

  # --- Include union ---

  Scenario: Include categories and event types form union
    Given a logger with file receiving all events and webhook including categories "write" and event types "auth_failure"
    When I audit a "user_create" event in category "write" with marker "union_w"
    And I audit an "auth_failure" event in category "security" with marker "union_s"
    And I audit a "permission_denied" event in category "security" with marker "union_p"
    Then the webhook receiver should have at least 2 events within 5 seconds
    And I close the logger
    And the file should contain "union_w"
    And the file should contain "union_s"
    And the file should contain "union_p"

  # --- Exclude event types ---

  Scenario: Exclude single event type removes only that event
    Given a logger with file receiving all events and webhook excluding event types "user_create"
    When I audit a "user_create" event in category "write" with marker "exc_single_w"
    And I audit a "config_update" event in category "write" with marker "exc_single_c"
    And I audit an "auth_failure" event in category "security" with marker "exc_single_s"
    Then the webhook receiver should have at least 2 events within 5 seconds
    And I close the logger
    And the file should contain "exc_single_w"
    And the file should contain "exc_single_c"
    And the file should contain "exc_single_s"

  Scenario: Exclude event types removes specific events
    Given a logger with file receiving all events and webhook excluding event types "user_create"
    When I audit a "user_create" event in category "write" with marker "excevt_w"
    And I audit an "auth_failure" event in category "security" with marker "excevt_s"
    Then the webhook receiver should have at least 1 event within 5 seconds
    And I close the logger
    And the file should contain "excevt_w"
    And the file should contain "excevt_s"

  # --- Empty route ---

  Scenario: Exclude multiple categories delivers union of exclusions
    Given a logger with file receiving all events and webhook excluding categories "write" and "read"
    When I audit a "user_create" event in category "write" with marker "exc_multi_w"
    And I audit a "user_get" event in category "read" with marker "exc_multi_r"
    And I audit an "auth_failure" event in category "security" with marker "exc_multi_s"
    Then the webhook receiver should have at least 1 event within 5 seconds
    And I close the logger
    And the file should contain "exc_multi_w"
    And the file should contain "exc_multi_r"
    And the file should contain "exc_multi_s"

  Scenario: Empty route delivers all globally enabled events
    Given a logger with file and webhook both receiving all events
    When I audit a "user_create" event in category "write" with marker "empty_w"
    And I audit an "auth_failure" event in category "security" with marker "empty_s"
    Then the webhook receiver should have at least 2 events within 5 seconds
    And I close the logger
    And the file should contain "empty_w"
    And the file should contain "empty_s"

  # --- Runtime changes ---

  Scenario: SetOutputRoute changes routing at runtime
    Given a logger with file and webhook both receiving all events
    When I audit a "user_create" event in category "write" with marker "pre_route"
    And the webhook receiver should have at least 1 event within 5 seconds
    And I set the webhook output route to include only "security"
    And I audit an "auth_failure" event in category "security" with marker "post_route_s"
    And I audit a "user_create" event in category "write" with marker "post_route_w"
    Then the webhook receiver should have at least 2 events within 5 seconds
    And I close the logger

  Scenario: Exclude event types and categories form union
    Given a logger with file receiving all events and webhook excluding categories "read" and event types "config_update"
    When I audit a "user_create" event in category "write" with marker "exc_union_w"
    And I audit a "config_update" event in category "write" with marker "exc_union_cu"
    And I audit a "user_get" event in category "read" with marker "exc_union_r"
    And I audit an "auth_failure" event in category "security" with marker "exc_union_s"
    Then the webhook receiver should have at least 2 events within 5 seconds
    And I close the logger
    And the file should contain "exc_union_w"
    And the file should contain "exc_union_cu"
    And the file should contain "exc_union_r"
    And the file should contain "exc_union_s"

  Scenario: ClearOutputRoute resets to all events
    Given a logger with file receiving all events and webhook receiving only "security"
    When I clear the webhook output route
    And I audit a "user_create" event in category "write" with marker "clear_w"
    Then the webhook receiver should have at least 1 event within 5 seconds
    And I close the logger
    And the file should contain "clear_w"

  Scenario: Include multiple categories delivers union
    Given a logger with file receiving all events and webhook including categories "write" and "security"
    When I audit a "user_create" event in category "write" with marker "multi_inc_w"
    And I audit an "auth_failure" event in category "security" with marker "multi_inc_s"
    And I audit a "user_get" event in category "read" with marker "multi_inc_r"
    Then the webhook receiver should have at least 2 events within 5 seconds
    And I close the logger
    And the file should contain "multi_inc_w"
    And the file should contain "multi_inc_s"
    And the file should contain "multi_inc_r"

  Scenario: OutputRoute returns current route
    Given a logger with file receiving all events and webhook receiving only "security"
    When I query the webhook output route
    Then the route should include category "security"

  Scenario: Unknown output name in SetOutputRoute returns error
    Given a logger with file receiving all events and webhook receiving only "security"
    When I try to set route for unknown output "nonexistent"
    Then the operation should return an error matching:
      """
      audit: unknown output "nonexistent"
      """

  # --- Global filter precedence ---

  Scenario: Global filter takes precedence over per-output route
    Given a logger with file receiving all events and webhook receiving only "security"
    When I disable category "security"
    And I audit an "auth_failure" event in category "security" with marker "global_sec"
    And I close the logger
    Then the file should not contain "global_sec"

@core @middleware
Feature: HTTP Middleware
  As a library consumer, I want HTTP middleware that automatically
  captures transport metadata so that every API request generates
  an audit event without manual instrumentation.

  Background:
    Given a middleware test taxonomy
    And a logger with file output at a temporary path

  # --- Transport metadata ---

  Scenario: HTTP request generates audit event with method and path
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource"
    And I close the logger
    Then the file should contain an event with event_type "api_request"
    And the file event should have field "method" with value "GET"
    And the file event should have field "path" with value "/api/resource"

  Scenario: POST request captures correct method
    Given an HTTP test server with audit middleware
    When I send a POST request to "/api/resource"
    And I close the logger
    Then the file event should have field "method" with value "POST"

  Scenario: Response status code captured
    Given an HTTP test server with audit middleware returning status 201
    When I send a POST request to "/api/resource"
    And I close the logger
    Then the file event should have field "status_code" with value "201"

  # --- Hints ---

  Scenario: Handler populates hints for domain-specific fields
    Given an HTTP test server with audit middleware that sets actor_id
    When I send a GET request to "/api/resource"
    And I close the logger
    Then the file event should have field "actor_id" with value "handler-actor"

  # --- Skip ---

  Scenario: Skip true prevents audit event
    Given an HTTP test server with audit middleware that skips GET requests
    When I send a GET request to "/api/resource"
    And I close the logger
    Then the file should have no events

  # --- Nil logger ---

  Scenario: Nil logger passes through without error
    Given an HTTP test server with nil logger middleware
    When I send a GET request to "/api/resource"
    Then the response status should be 200

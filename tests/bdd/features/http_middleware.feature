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

  # --- Client IP extraction ---

  Scenario: Client IP extracted from X-Forwarded-For
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource" with header "X-Forwarded-For" = "10.0.0.1, 192.168.1.1"
    And I close the logger
    Then the file event should have field "source_ip" with value "192.168.1.1"

  Scenario: Client IP falls back to X-Real-IP
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource" with header "X-Real-IP" = "10.0.0.55"
    And I close the logger
    Then the file event should have field "source_ip" with value "10.0.0.55"

  # --- Request ID ---

  Scenario: Request ID extracted from header
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource" with header "X-Request-Id" = "req-abc-123"
    And I close the logger
    Then the file event should have field "request_id" with value "req-abc-123"

  Scenario: Request ID generated when header missing
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource"
    And I close the logger
    Then the file event should have field "request_id" present

  # --- User-Agent ---

  Scenario: User-Agent captured in audit event
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource" with header "User-Agent" = "test-agent/1.0"
    And I close the logger
    Then the file event should have field "user_agent" with value "test-agent/1.0"

  # --- Default status ---

  Scenario: Default status 200 if handler writes nothing
    Given an HTTP test server with audit middleware returning no explicit status
    When I send a GET request to "/api/resource"
    And I close the logger
    Then the file event should have field "status_code" with value "200"

  # --- Path truncation ---

  Scenario: Invalid request ID header replaced with generated UUID
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource" with header "X-Request-Id" = "has\nnewline"
    And I close the logger
    Then the file event should have field "request_id" present

  Scenario: Concurrent requests get independent audit events
    Given an HTTP test server with audit middleware
    When I send 10 concurrent GET requests to "/api/resource"
    And I close the logger
    Then the file should contain exactly 10 events

  Scenario: Long User-Agent is truncated to 512 characters
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource" with a 1000-char User-Agent
    And I close the logger
    Then the file event user_agent field should be at most 512 characters

  Scenario: Long path is truncated
    Given an HTTP test server with audit middleware
    When I send a GET request to a path with 3000 characters
    And I close the logger
    Then the file event path field should be at most 2048 characters

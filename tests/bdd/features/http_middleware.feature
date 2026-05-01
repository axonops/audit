@core @middleware
Feature: HTTP Middleware
  As a library consumer, I want HTTP middleware that automatically
  captures transport metadata so that every API request generates
  an audit event without manual instrumentation.

  Background:
    Given a middleware test taxonomy
    And an auditor with file output at a temporary path

  # --- Transport metadata ---

  Scenario: HTTP request generates audit event with method and path
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource"
    And I close the auditor
    Then the file should contain an event with event_type "api_request"
    And the file event should have field "method" with value "GET"
    And the file event should have field "path" with value "/api/resource"

  Scenario: POST request captures correct method
    Given an HTTP test server with audit middleware
    When I send a POST request to "/api/resource"
    And I close the auditor
    Then the file event should have field "method" with value "POST"

  Scenario: Response status code captured
    Given an HTTP test server with audit middleware returning status 201
    When I send a POST request to "/api/resource"
    And I close the auditor
    Then the file event should have field "status_code" with value "201"

  # --- Hints ---

  Scenario: Handler populates hints for domain-specific fields
    Given an HTTP test server with audit middleware that sets actor_id
    When I send a GET request to "/api/resource"
    And I close the auditor
    Then the file event should have field "actor_id" with value "handler-actor"

  Scenario: Handler populates hints Extra fields
    Given an HTTP test server with audit middleware that sets Extra hints
    When I send a GET request to "/api/resource"
    And I close the auditor
    Then the file event should have field "custom_field" with value "custom_value"

  # --- Skip ---

  Scenario: Skip true prevents audit event
    Given an HTTP test server with audit middleware that skips GET requests
    When I send a GET request to "/api/resource"
    And I close the auditor
    Then the file should have no events

  # --- Nil auditor ---

  Scenario: Nil auditor passes through without error
    Given an HTTP test server with nil auditor middleware
    When I send a GET request to "/api/resource"
    Then the response status should be 200

  # --- Client IP extraction ---

  Scenario: Client IP extracted from X-Forwarded-For
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource" with header "X-Forwarded-For" = "10.0.0.1, 192.168.1.1"
    And I close the auditor
    Then the file event should have field "source_ip" with value "192.168.1.1"

  Scenario: Client IP falls back to X-Real-IP
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource" with header "X-Real-IP" = "10.0.0.55"
    And I close the auditor
    Then the file event should have field "source_ip" with value "10.0.0.55"

  Scenario: PUT request captures correct method
    Given an HTTP test server with audit middleware
    When I send a PUT request to "/api/resource"
    And I close the auditor
    Then the file event should have field "method" with value "PUT"

  Scenario: DELETE request captures correct method
    Given an HTTP test server with audit middleware
    When I send a DELETE request to "/api/resource"
    And I close the auditor
    Then the file event should have field "method" with value "DELETE"

  # --- Request ID ---

  Scenario: Request ID extracted from header
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource" with header "X-Request-Id" = "req-abc-123"
    And I close the auditor
    Then the file event should have field "request_id" with value "req-abc-123"

  Scenario: Request ID generated when header missing
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource"
    And I close the auditor
    Then the file event should have field "request_id" present

  # --- User-Agent ---

  Scenario: User-Agent captured in audit event
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource" with header "User-Agent" = "test-agent/1.0"
    And I close the auditor
    Then the file event should have field "user_agent" with value "test-agent/1.0"

  # --- Default status ---

  Scenario: Default status 200 if handler writes nothing
    Given an HTTP test server with audit middleware returning no explicit status
    When I send a GET request to "/api/resource"
    And I close the auditor
    Then the file event should have field "status_code" with value "200"

  # --- Path truncation ---

  Scenario: Invalid request ID header replaced with generated UUID
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource" with header "X-Request-Id" = "has\nnewline"
    And I close the auditor
    Then the file event should have field "request_id" present

  Scenario: Too-long request ID replaced with generated UUID
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource" with a 200-char X-Request-Id
    And I close the auditor
    Then the file event request_id should be shorter than 200 characters

  # --- TLS state detection ---

  Scenario: Non-TLS request reports transport security "none"
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource"
    And I close the auditor
    Then the file event should have field "transport_security" with value "none"

  Scenario: TLS request reports transport security "tls"
    Given an HTTPS test server with audit middleware
    When I send a GET request to "/api/secure" via TLS
    And I close the auditor
    Then the file event should have field "transport_security" with value "tls"

  # --- Panic recovery ---

  Scenario: Handler panic produces audit event and re-raises
    Given an HTTP test server with panicking handler and audit middleware
    When I send a GET request to "/api/panic" expecting panic
    And I close the auditor
    Then the file should contain events

  # --- #491 — placement relative to panic-recovery middleware ---

  Scenario: Middleware placed outside panic recovery records event then re-panics
    # CORRECT placement: audit middleware wraps a downstream recovery
    # middleware, which in turn wraps the handler. The handler panics;
    # the recovery middleware catches and renders 500; the audit
    # middleware observes the 500 and records the audit event. This is
    # the documented pattern — see docs/http-middleware.md §Placement.
    Given an HTTP test server with audit outside recovery middleware and panicking handler
    When I send a GET request to "/api/panic" expecting panic
    And I close the auditor
    Then the response status should be 500
    And the file event should have field "status_code" with value "500"
    And the file event should have field "path" with value "/api/panic"

  Scenario: Middleware placed inside panic recovery — known-wrong pattern
    # DISCOURAGED placement — recorded here to document the observable
    # outcome. The outer recovery middleware runs LAST, so the panic
    # travels out from the handler through audit (which re-raises
    # after recording) and into the outer recovery. Some recovery
    # middlewares double-recover safely; others swallow the re-raise
    # with inconsistent status reporting. The audit event IS still
    # recorded via the audit middleware's own internal recovery — but
    # this placement couples audit's error reporting to whichever
    # recovery middleware sits outside it. See
    # docs/http-middleware.md §Placement for why this is fragile.
    Given an HTTP test server with audit inside recovery middleware and panicking handler
    When I send a GET request to "/api/panic" expecting panic
    And I close the auditor
    Then the file should contain events
    And the file event should have field "path" with value "/api/panic"

  Scenario: Builder panic is recovered and logged
    Given an HTTP test server with panicking builder and audit middleware
    When I send a GET request to "/api/resource"
    And I close the auditor
    Then the file should have no events

  Scenario: Builder panic forces skip=true and the HTTP response is unaffected
    # F-20 — explicitly pin the contract: when an EventBuilder panics,
    # the middleware's recover() handler forces skip=true so no audit
    # event is emitted, AND the downstream HTTP response is unaffected
    # (200 OK passes through to the client). The panic occurs in the
    # middleware's deferred post-handler audit emission, not the
    # request path. The earlier "Builder panic is recovered and logged"
    # scenario asserts no events; this scenario adds the response-side
    # invariant (the client never sees the panic).
    Given an HTTP test server with panicking builder and audit middleware
    When I send a GET request to "/api/resource"
    And I close the auditor
    Then the response status should be 200
    And the file should have no events

  Scenario: Concurrent requests get independent audit events
    Given an HTTP test server with audit middleware
    When I send 10 concurrent GET requests to "/api/resource"
    And I close the auditor
    Then the file should contain exactly 10 events

  Scenario: User-Agent at exactly 512 chars is not truncated
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource" with a 512-char User-Agent
    And I close the auditor
    Then the file event user_agent field should be exactly 512 characters

  Scenario: Long User-Agent is truncated to 512 characters
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource" with a 1000-char User-Agent
    And I close the auditor
    Then the file event user_agent field should be at most 512 characters

  Scenario: Multibyte UTF-8 not split at truncation boundary
    Given an HTTP test server with audit middleware
    When I send a GET request to "/api/resource" with a User-Agent ending in multibyte at 512
    And I close the auditor
    Then the file event user_agent should be valid UTF-8

  Scenario: Long path is truncated
    Given an HTTP test server with audit middleware
    When I send a GET request to a path with 3000 characters
    And I close the auditor
    Then the file event path field should be at most 2048 characters

@webhook @docker
Feature: Webhook Output
  As a library consumer, I want to send audit events to an HTTP endpoint
  so that I can integrate with cloud SIEM, Splunk, or custom receivers.

  The webhook output batches events as NDJSON, retries on 5xx/429, drops
  on 4xx, prevents SSRF, supports custom headers, and flushes on shutdown.

  Background:
    Given a standard test taxonomy

  # --- Batch delivery ---

  Scenario: Batch delivery sends events in batches
    Given a logger with webhook output configured for batch size 5
    When I audit 12 uniquely marked webhook events
    Then the webhook receiver should have at least 3 requests within 10 seconds

  Scenario: Single event with batch size 1 delivered immediately
    Given a logger with webhook output configured for batch size 1
    When I audit a uniquely marked webhook "user_create" event
    Then the webhook receiver should have at least 1 event within 5 seconds

  Scenario: Flush interval triggers delivery before batch full
    Given a logger with webhook output configured for batch size 100 and flush interval 200ms
    When I audit a uniquely marked webhook "user_create" event
    Then the webhook receiver should have at least 1 event within 5 seconds

  # --- Retry logic ---

  Scenario: Retry on 503 response with eventual delivery
    Given the webhook receiver is configured to return status 503
    And a logger with webhook output configured for batch size 1 and max retries 3
    When I audit a uniquely marked webhook "user_create" event
    And the webhook receiver is reconfigured to return status 200
    Then the webhook receiver should have at least 1 event within 10 seconds

  Scenario: Retry on 429 rate limit response
    Given the webhook receiver is configured to return status 429
    And a logger with webhook output configured for batch size 1 and max retries 3
    When I audit a uniquely marked webhook "user_create" event
    And the webhook receiver is reconfigured to return status 200
    Then the webhook receiver should have at least 1 event within 10 seconds

  Scenario: No retry on 400 bad request
    Given the webhook receiver is configured to return status 400
    And a logger with webhook output configured for batch size 1 and max retries 5
    When I audit a uniquely marked webhook "user_create" event "first"
    And the webhook receiver is reconfigured to return status 200
    And I audit a uniquely marked webhook "user_create" event "sentinel"
    Then the webhook receiver should have exactly 2 events within 5 seconds

  Scenario: No retry on 401 unauthorized
    Given the webhook receiver is configured to return status 401
    And a logger with webhook output configured for batch size 1 and max retries 5
    When I audit a uniquely marked webhook "user_create" event "no_retry_401"
    And the webhook receiver is reconfigured to return status 200
    And I audit a uniquely marked webhook "user_create" event "sentinel_401"
    Then the webhook receiver should have exactly 2 events within 5 seconds

  Scenario: No retry on 403 forbidden
    Given the webhook receiver is configured to return status 403
    And a logger with webhook output configured for batch size 1 and max retries 5
    When I audit a uniquely marked webhook "user_create" event "no_retry_403"
    And the webhook receiver is reconfigured to return status 200
    And I audit a uniquely marked webhook "user_create" event "sentinel_403"
    Then the webhook receiver should have exactly 2 events within 5 seconds

  # --- Custom headers ---

  Scenario: Custom headers delivered with events
    Given a logger with webhook output with custom header "X-Audit-Source" = "bdd-test"
    When I audit a uniquely marked webhook "user_create" event
    Then the webhook receiver should have at least 1 event within 5 seconds
    And the received webhook event should have header "X-Audit-Source" with value "bdd-test"

  Scenario: Content-Type is application/x-ndjson
    Given a logger with webhook output configured for batch size 1
    When I audit a uniquely marked webhook "user_create" event
    Then the webhook receiver should have at least 1 event within 5 seconds
    And the received webhook event should have header "Content-Type" with value "application/x-ndjson"

  # --- Shutdown flush ---

  Scenario: Pending events flushed on shutdown
    Given a logger with webhook output configured for batch size 100 and flush interval 60s
    When I audit 3 uniquely marked webhook events
    And I close the logger
    Then the webhook receiver should have at least 1 event within 5 seconds

  # --- SSRF protection ---

  Scenario: HTTP URL rejected unless AllowInsecureHTTP is true
    When I try to create a webhook output to "http://localhost:8080/events" without AllowInsecureHTTP
    Then the webhook construction should fail with an error

  Scenario: AllowInsecureHTTP permits http URLs
    Given a logger with webhook output to "http://localhost:8080/events" with AllowInsecureHTTP
    When I audit a uniquely marked webhook "user_create" event
    Then the webhook receiver should have at least 1 event within 5 seconds

  Scenario: Embedded credentials in URL rejected
    When I try to create a webhook output to "https://user:pass@example.com/events"
    Then the webhook construction should fail with an error containing "credentials"

  Scenario: Header CRLF injection rejected
    When I try to create a webhook output with header containing CRLF
    Then the webhook construction should fail with an error

  # --- Config validation ---

  Scenario: Empty URL rejected
    When I try to create a webhook output to ""
    Then the webhook construction should fail with an error containing "url"

  Scenario: BatchSize exceeding maximum rejected
    When I try to create a webhook output with batch size 20000
    Then the webhook construction should fail with an error

  Scenario: MaxRetries exceeding maximum rejected
    When I try to create a webhook output with max retries 50
    Then the webhook construction should fail with an error

  # --- Complete payload verification ---

  Scenario: All event fields present in webhook delivery
    Given a logger with webhook output configured for batch size 1
    When I audit event "user_create" with fields:
      | field     | value         |
      | outcome   | success       |
      | actor_id  | alice         |
      | marker    | webhook_all   |
      | target_id | user-42       |
    Then the webhook receiver should have at least 1 event within 5 seconds
    And the webhook event body should contain field "event_type" with value "user_create"
    And the webhook event body should contain field "outcome" with value "success"
    And the webhook event body should contain field "actor_id" with value "alice"
    And the webhook event body should contain field "marker" with value "webhook_all"
    And the webhook event body should contain field "target_id" with value "user-42"
    And the webhook event body should contain field "timestamp"

  # --- Retry on other 5xx ---

  Scenario: Retry on 500 internal server error
    Given the webhook receiver is configured to return status 500
    And a logger with webhook output configured for batch size 1 and max retries 3
    When I audit a uniquely marked webhook "user_create" event
    And the webhook receiver is reconfigured to return status 200
    Then the webhook receiver should have at least 1 event within 10 seconds

  Scenario: Retry on 502 bad gateway
    Given the webhook receiver is configured to return status 502
    And a logger with webhook output configured for batch size 1 and max retries 3
    When I audit a uniquely marked webhook "user_create" event
    And the webhook receiver is reconfigured to return status 200
    Then the webhook receiver should have at least 1 event within 10 seconds

  # --- Buffer management ---

  Scenario: Buffer overflow drops event without blocking
    Given a logger with webhook output configured for batch size 100 and flush interval 60s
    When I rapidly audit 200 webhook events
    Then the audit calls should not have blocked

  # --- Close idempotent ---

  Scenario: Close is idempotent
    Given a logger with webhook output configured for batch size 1
    When I close the logger
    And I close the logger again
    Then the second close should return no error

  # --- Lifecycle ---

  Scenario: Write after close returns error
    Given a logger with webhook output configured for batch size 1
    When I close the logger
    And I try to audit event "user_create" with required fields
    Then the audit call should return an error containing "closed"

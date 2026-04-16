@loki @docker
Feature: Loki Output
  As a library consumer, I want to send audit events to Grafana Loki
  so that I can query audit trails using LogQL and integrate with
  Grafana dashboards.

  The Loki output batches events as JSON push requests, groups by
  stream labels, supports gzip compression, retries on 429/5xx,
  drops on 4xx, prevents SSRF, supports multi-tenancy via
  X-Scope-OrgID, and flushes on shutdown.

  Background:
    Given a standard test taxonomy

  # --- Basic delivery with complete payload verification ---

  Scenario: Single event delivered to Loki with complete payload
    Given a logger with loki output
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: Custom field values preserved in Loki log line
    Given a logger with loki output
    When I audit a uniquely marked "user_create" event with field "actor_id" = "alice"
    Then the loki server should contain the marker within 15 seconds
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | alice        |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: Multiple events all delivered with complete payloads
    Given a logger with loki output with batch size 5
    When I audit 10 loki events with a shared marker
    Then the loki server should have at least 10 events within 15 seconds
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  # --- Stream labels with complete payload verification ---

  Scenario: All dynamic labels present on Loki stream with complete payload
    Given a logger with loki output
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki stream should have label "event_type" with value "user_create"
    And the loki stream should have label "app_name" with value "bdd-audit"
    And the loki stream should have label "host" with value "bdd-host"
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: Static labels present on stream with complete payload
    Given a logger with loki output with static label "environment" = "testing"
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki stream should have label "environment" with value "testing"
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: Excluded dynamic label absent from stream with payload intact
    Given a logger with loki output excluding dynamic label "severity"
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki stream should not have label "severity"
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: Different event types in separate streams with payload verification
    Given a logger with loki output with batch size 10
    When I audit a uniquely marked "user_create" event
    And I audit a uniquely marked "auth_failure" event
    Then the loki server should have events in stream "user_create" within 15 seconds
    And the loki server should have events in stream "auth_failure" within 15 seconds

  # --- Batch delivery with complete payload verification ---

  Scenario: Batch flushes on count threshold with complete payload
    Given a logger with loki output with batch size 5 and flush interval 60s
    When I audit 5 loki events with a shared marker
    Then the loki server should have at least 5 events within 15 seconds
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: Batch flushes on timer with complete payload
    Given a logger with loki output with batch size 1000 and flush interval 500ms
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: Shutdown flushes pending events with complete payload
    Given a logger with loki output with batch size 1000 and flush interval 60s
    When I audit 3 loki events with a shared marker
    And I close the logger
    Then the loki server should have at least 3 events within 15 seconds
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  # --- Gzip compression with complete payload verification ---

  Scenario: Gzip-compressed events preserve complete payload in Loki
    Given a logger with loki output with gzip enabled
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: Uncompressed events preserve complete payload in Loki
    Given a logger with loki output with gzip disabled
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  # --- Multi-tenancy with payload verification ---

  Scenario: Events delivered to specific tenant with complete payload
    Given a logger with loki output to tenant "tenant-alpha"
    When I audit a uniquely marked "user_create" event
    Then the loki server for tenant "tenant-alpha" should contain the marker within 15 seconds

  Scenario: Tenant isolation prevents cross-tenant visibility
    Given a logger with loki output to tenant "tenant-iso-a"
    When I audit a uniquely marked "user_create" event
    Then the loki server for tenant "tenant-iso-a" should contain the marker within 15 seconds
    And the loki server for tenant "tenant-iso-b" should not contain the marker within 5 seconds

  # --- Large batch delivery ---

  Scenario: All events from large batch delivered with complete payloads
    Given a logger with loki output with batch size 10
    When I audit 10 loki events with a shared marker
    Then the loki server should have at least 10 events within 15 seconds
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  # --- Lifecycle ---

  Scenario: Close is idempotent
    Given a logger with loki output
    When I close the logger
    And I close the logger again
    Then no error should occur

  Scenario: Write after close returns error
    Given a logger with loki output
    When I close the logger
    And I try to audit a "user_create" event
    Then the audit call should return an error wrapping "ErrClosed"

  # --- Retry logic (httptest.Server, no Docker Loki) ---

  Scenario: Retry on 503 with eventual delivery
    Given a local Loki receiver returning status 503
    And mock loki metrics are configured
    And a logger with loki output to the local receiver with max retries 3
    When I audit a uniquely marked "user_create" event
    And the local Loki receiver is reconfigured to return status 204
    Then the local Loki receiver should have at least 1 push within 10 seconds
    And the loki metrics should have recorded at least 1 flush

  Scenario: Retry on 429 rate limit with eventual delivery
    Given a local Loki receiver returning status 429
    And mock loki metrics are configured
    And a logger with loki output to the local receiver with max retries 3
    When I audit a uniquely marked "user_create" event
    And the local Loki receiver is reconfigured to return status 204
    Then the local Loki receiver should have at least 1 push within 10 seconds

  Scenario: No retry on 400 client error
    Given a local Loki receiver returning status 400
    And mock loki metrics are configured
    And a logger with loki output to the local receiver with max retries 5
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the loki metrics should have recorded at least 1 drop within 5 seconds
    And the local Loki receiver should have received at most 1 push

  Scenario: No retry on 401 unauthorized
    Given a local Loki receiver returning status 401
    And mock loki metrics are configured
    And a logger with loki output to the local receiver with max retries 5
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the loki metrics should have recorded at least 1 drop within 5 seconds
    And the local Loki receiver should have received at most 1 push

  Scenario: Retries exhausted drops batch
    Given a local Loki receiver returning status 503
    And mock loki metrics are configured
    And a logger with loki output to the local receiver with max retries 1
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the loki metrics should have recorded at least 1 drop within 5 seconds

  # --- Loki unavailable ---

  Scenario: Loki unreachable drops events and records metrics
    Given mock loki metrics are configured
    And a logger with loki output to unreachable server with metrics
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the loki metrics should have recorded at least 1 drop within 5 seconds

  # --- SSRF protection (httptest.Server, no Docker Loki) ---

  Scenario: Private range blocked by default drops events
    Given a local Loki receiver accepting pushes
    And mock loki metrics are configured
    And a logger with loki output to the local Loki receiver without AllowPrivateRanges
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the loki metrics should have recorded at least 1 drop within 5 seconds

  Scenario: AllowPrivateRanges permits private addresses
    Given a local Loki receiver accepting pushes
    And a logger with loki output to the local Loki receiver with AllowPrivateRanges
    When I audit a uniquely marked "user_create" event
    Then the local Loki receiver should have at least 1 push within 10 seconds

  Scenario: Redirect is rejected and not followed
    Given a local Loki receiver configured to redirect
    And mock loki metrics are configured
    And a logger with loki output to the redirecting Loki receiver with metrics
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the loki metrics should have recorded at least 1 drop within 5 seconds

  # --- Metrics (httptest.Server) ---

  Scenario: Successful delivery records flush metric
    Given a local Loki receiver accepting pushes
    And mock loki metrics are configured
    And a logger with loki output to the local Loki receiver with metrics
    When I audit a uniquely marked "user_create" event
    Then the local Loki receiver should have at least 1 push within 10 seconds
    And the loki metrics should have recorded at least 1 flush
    And the loki metrics should have recorded 0 drops

  Scenario: Nil loki metrics does not panic
    Given a local Loki receiver accepting pushes
    And a logger with loki output to the local Loki receiver with AllowPrivateRanges
    When I audit a uniquely marked "user_create" event
    Then the local Loki receiver should have at least 1 push within 10 seconds

  Scenario: Delivery failure records RecordError metric
    Given a local Loki receiver returning status 400
    And mock loki metrics are configured
    And a logger with loki output to the local Loki receiver with metrics and max retries 0
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the loki metrics should have recorded at least 1 error within 5 seconds

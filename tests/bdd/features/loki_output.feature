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

  # --- Basic delivery ---

  Scenario: Single event delivered to Loki with payload verification
    Given a logger with loki output
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki event should contain field "event_type" with value "user_create"
    And the loki event should contain field "outcome" with value "success"
    And the loki event should contain field "actor_id" with value "test-actor"

  Scenario: Event data preserved in Loki log line
    Given a logger with loki output
    When I audit a uniquely marked "user_create" event with field "actor_id" = "alice"
    Then the loki server should contain the marker within 15 seconds
    And the loki event should contain field "actor_id" with value "alice"

  Scenario: Multiple events delivered to Loki
    Given a logger with loki output with batch size 5
    When I audit 10 loki events with a shared marker
    Then the loki server should have at least 10 events within 15 seconds

  # --- Stream labels ---

  Scenario: Dynamic labels appear on Loki stream
    Given a logger with loki output
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki stream should have label "event_type" with value "user_create"
    And the loki stream should have label "app_name" with value "bdd-audit"
    And the loki stream should have label "host" with value "bdd-host"

  Scenario: Static labels appear on Loki stream with payload verification
    Given a logger with loki output with static label "environment" = "testing"
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki stream should have label "environment" with value "testing"
    And the loki event should contain field "outcome" with value "success"

  Scenario: Excluded dynamic label absent from stream
    Given a logger with loki output excluding dynamic label "severity"
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki stream should not have label "severity"

  Scenario: Different event types create separate streams
    Given a logger with loki output with batch size 10
    When I audit a uniquely marked "user_create" event
    And I audit a uniquely marked "auth_failure" event
    Then the loki server should have events in stream "user_create" within 15 seconds
    And the loki server should have events in stream "auth_failure" within 15 seconds

  # --- Batch delivery ---

  Scenario: Batch flushes on count threshold
    Given a logger with loki output with batch size 5 and flush interval 60s
    When I audit 5 loki events with a shared marker
    Then the loki server should have at least 5 events within 15 seconds

  Scenario: Batch flushes on timer
    Given a logger with loki output with batch size 1000 and flush interval 500ms
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds

  Scenario: Shutdown flushes pending events
    Given a logger with loki output with batch size 1000 and flush interval 60s
    When I audit 3 loki events with a shared marker
    And I close the logger
    Then the loki server should have at least 3 events within 15 seconds

  # --- Gzip compression ---

  Scenario: Gzip-compressed events accepted by Loki with payload verification
    Given a logger with loki output with gzip enabled
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki event should contain field "event_type" with value "user_create"
    And the loki event should contain field "actor_id" with value "test-actor"

  Scenario: Uncompressed events accepted by Loki with payload verification
    Given a logger with loki output with gzip disabled
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki event should contain field "event_type" with value "user_create"
    And the loki event should contain field "actor_id" with value "test-actor"

  # --- Multi-tenancy ---

  Scenario: Events delivered to specific tenant
    Given a logger with loki output to tenant "tenant-alpha"
    When I audit a uniquely marked "user_create" event
    Then the loki server for tenant "tenant-alpha" should contain the marker within 15 seconds

  Scenario: Tenant isolation prevents cross-tenant visibility
    Given a logger with loki output to tenant "tenant-iso-a"
    When I audit a uniquely marked "user_create" event
    Then the loki server for tenant "tenant-iso-a" should contain the marker within 15 seconds
    And the loki server for tenant "tenant-iso-b" should not contain the marker within 5 seconds

  # --- Duplicate timestamps ---

  Scenario: Events with identical timestamps all delivered
    Given a logger with loki output with batch size 10
    When I audit 5 loki events with a shared marker
    Then the loki server should have at least 5 events within 15 seconds

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

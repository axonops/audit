@syslog @docker
Feature: Syslog Output
  As a library consumer, I want to send audit events to a syslog server
  so that they integrate with my centralised log management infrastructure.

  The syslog output supports TCP, UDP, and TCP+TLS (including mTLS)
  transports. Events are formatted as RFC 5424 structured syslog messages.
  UDP uses one-message-per-datagram (no octet-count framing). TCP uses
  RFC 5425 message-length framing. Reconnection uses bounded exponential
  backoff with jitter.

  Background:
    Given a standard test taxonomy

  # --- Transport variants ---

  Scenario: Deliver event over TCP plain
    Given a logger with syslog output on "tcp" to "localhost:5514"
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the syslog server should contain the marker within 10 seconds

  Scenario: Deliver event over UDP
    Given a logger with syslog output on "udp" to "127.0.0.1:5515"
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the syslog server should contain the marker within 10 seconds

  Scenario: Deliver event over TLS with CA certificate
    Given a logger with syslog TLS output to "localhost:6514" with CA cert
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the syslog server should contain the marker within 10 seconds

  Scenario: Deliver event over mTLS with client certificate
    Given a logger with syslog mTLS output to "localhost:6515"
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the syslog server should contain the marker within 10 seconds

  Scenario: Multiple events delivered over TCP
    Given a logger with syslog output on "tcp" to "localhost:5514"
    When I audit 5 uniquely marked events
    And I close the logger
    Then the syslog server should contain all 5 markers within 10 seconds

  # --- RFC 5424 format ---

  Scenario: Syslog message contains app name
    Given a logger with syslog output on "tcp" to "localhost:5514" with app name "bdd-audit"
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the syslog server should contain the marker within 10 seconds
    And the syslog line with the marker should contain "bdd-audit"

  Scenario: Syslog message contains timestamp
    Given a logger with syslog output on "tcp" to "localhost:5514"
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the syslog server should contain the marker within 10 seconds
    And the syslog line with the marker should contain the current year

  # --- TLS configuration errors ---

  Scenario: Invalid CA certificate rejected at construction
    When I try to create a syslog output on "tcp+tls" to "localhost:6514" with invalid CA
    Then the syslog construction should fail with an error containing "certificate"

  Scenario: TLS cert without key is rejected
    When I try to create a syslog output with TLS cert but no key
    Then the syslog construction should fail with an error containing "both be set"

  # --- Config validation ---

  Scenario: Empty address is rejected
    When I try to create a syslog output with empty address
    Then the syslog construction should fail with an error containing "address"

  Scenario: Invalid network type is rejected
    When I try to create a syslog output on "invalid" to "localhost:5514"
    Then the syslog construction should fail with an error containing "network"

  Scenario: Invalid facility is rejected
    When I try to create a syslog output with facility "bogus"
    Then the syslog construction should fail with an error containing "facility"

  Scenario: Default app name is "audit"
    Given a logger with syslog output on "tcp" to "localhost:5514"
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the syslog server should contain the marker within 10 seconds
    And the syslog line with the marker should contain "audit"

  # --- UDP edge cases ---

  Scenario: UDP large payload accepted without panic
    Given a logger with syslog output on "udp" to "127.0.0.1:5515"
    When I audit an event with a 4096-byte payload
    Then the audit call should return no error

  Scenario: UDP does not use octet-count framing
    Given a logger with syslog output on "udp" to "127.0.0.1:5515"
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the syslog server should contain the marker within 10 seconds

  # --- Lifecycle ---

  Scenario: Write after close returns error
    Given a logger with syslog output on "tcp" to "localhost:5514"
    When I close the logger
    And I try to audit event "user_create" with required fields
    Then the audit call should return an error containing "closed"

  # --- Syslog-specific metrics ---

  Scenario: Nil syslog metrics does not panic during delivery
    Given a logger with syslog output on "tcp" to "localhost:5514"
    When I audit a uniquely marked "user_create" event
    And I close the logger
    Then the syslog server should contain the marker within 10 seconds

  Scenario: Close is idempotent
    Given a logger with syslog output on "tcp" to "localhost:5514"
    When I audit a uniquely marked "user_create" event
    And I close the logger
    And I close the logger again
    Then the second close should return no error

  # --- Complete payload verification ---

  Scenario: All event fields present in syslog output
    Given a logger with syslog output on "tcp" to "localhost:5514"
    When I audit event "user_create" with fields:
      | field     | value      |
      | outcome   | success    |
      | actor_id  | alice      |
      | marker    | syslog_all |
      | target_id | user-42    |
    And I close the logger
    Then the syslog server should contain "syslog_all" within 10 seconds
    And the syslog line with "syslog_all" should contain "user_create"
    And the syslog line with "syslog_all" should contain "alice"

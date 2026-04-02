@core @hmac
Feature: HMAC Integrity Verification
  As a library consumer, I want per-output HMAC integrity verification
  so that I can detect if audit events have been tampered with after
  production.

  Background:
    Given a standard test taxonomy

  # --- HMAC presence ---

  Scenario: HMAC fields present when enabled
    Given a logger with stdout output and HMAC enabled using salt "test-salt-sixteen-b!" version "v1" and hash "HMAC-SHA-256"
    When I audit event "user_create" with required fields
    And I close the logger
    Then the output should contain "_hmac" field
    And the output should contain "_hmac_v" field with value "v1"

  Scenario: HMAC fields absent when not configured
    Given a logger with stdout output
    When I audit event "user_create" with required fields
    And I close the logger
    Then the output should not contain "_hmac" field
    And the output should not contain "_hmac_v" field

  # --- Independent verification ---

  Scenario: HMAC is independently verifiable with HMAC-SHA-256
    Given a logger with stdout output and HMAC enabled using salt "verify-test-salt-16!" version "v1" and hash "HMAC-SHA-256"
    When I audit event "user_create" with required fields
    And I close the logger
    Then independently recomputing HMAC-SHA-256 over the payload with salt "verify-test-salt-16!" matches the "_hmac" value

  # --- Salt version ---

  Scenario: Salt version appears in output
    Given a logger with stdout output and HMAC enabled using salt "version-test-salt-16" version "2026-Q1" and hash "HMAC-SHA-256"
    When I audit event "user_create" with required fields
    And I close the logger
    Then the output should contain "_hmac_v" field with value "2026-Q1"

  # --- Validation ---

  Scenario: Salt too short rejected at startup
    When I try to create a logger with HMAC salt "short" version "v1" and hash "HMAC-SHA-256"
    Then logger creation should fail with an error containing "at least"

  Scenario: Unknown algorithm rejected at startup
    When I try to create a logger with HMAC salt "valid-salt-sixteen-b!" version "v1" and hash "MD5"
    Then logger creation should fail with an error containing "unknown"

  Scenario: Missing salt version rejected at startup
    When I try to create a logger with HMAC salt "valid-salt-sixteen-b!" version "" and hash "HMAC-SHA-256"
    Then logger creation should fail with an error containing "version"

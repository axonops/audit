@core @hmac
Feature: HMAC Integrity Verification
  As a library consumer, I want per-output HMAC integrity verification
  so that I can detect if audit events have been tampered with after
  production.

  Background:
    Given a standard test taxonomy

  # --- HMAC presence ---

  Scenario: HMAC fields present when enabled
    Given an auditor with stdout output and HMAC enabled using salt "test-salt-sixteen-b!" version "v1" and hash "HMAC-SHA-256"
    When I audit event "user_create" with required fields
    And I close the auditor
    Then the output should contain "_hmac" field
    And the output should contain "_hmac_v" field with value "v1"

  Scenario: HMAC fields absent when not configured
    Given an auditor with stdout output
    When I audit event "user_create" with required fields
    And I close the auditor
    Then the output should not contain "_hmac" field
    And the output should not contain "_hmac_v" field

  # --- Independent verification ---

  Scenario: HMAC is independently verifiable with HMAC-SHA-256
    Given an auditor with stdout output and HMAC enabled using salt "verify-test-salt-16!" version "v1" and hash "HMAC-SHA-256"
    When I audit event "user_create" with required fields
    And I close the auditor
    Then independently recomputing HMAC-SHA-256 over the payload with salt "verify-test-salt-16!" matches the "_hmac" value

  # --- Salt version ---

  Scenario: Salt version appears in output
    Given an auditor with stdout output and HMAC enabled using salt "version-test-salt-16" version "2026-Q1" and hash "HMAC-SHA-256"
    When I audit event "user_create" with required fields
    And I close the auditor
    Then the output should contain "_hmac_v" field with value "2026-Q1"

  # --- Field stripping changes the HMAC ---

  Scenario: HMAC differs when sensitivity labels strip fields
    Given a taxonomy with PII sensitivity labels:
      """
      version: 1
      categories:
        write:
          events:
            - user_create
      sensitivity:
        labels:
          pii:
            description: "Personally identifiable information"
            fields: [email]
      events:
        user_create:
          fields:
            outcome: {required: true}
            actor_id: {required: true}
            email:
              labels: [pii]
      """
    And two HMAC-enabled outputs where "stripped" excludes label "pii" using salts "full-salt-sixteen-b!" and "stripped-salt-16-byt"
    When I audit event "user_create" with fields:
      | field    | value             |
      | outcome  | success           |
      | actor_id | alice             |
      | email    | alice@example.com |
    And I close the auditor
    Then output "full" should contain field "email" with value "alice@example.com"
    And output "stripped" should not contain field "email"
    And both outputs should have "_hmac" fields
    And the "_hmac" values should differ between "full" and "stripped"
    And output "full" HMAC should verify with salt "full-salt-sixteen-b!"
    And output "stripped" HMAC should verify with salt "stripped-salt-16-byt"
    And output "full" HMAC should NOT verify with salt "stripped-salt-16-byt"
    And output "stripped" HMAC should NOT verify with salt "full-salt-sixteen-b!"

  # --- Validation ---

  Scenario: Salt too short rejected at startup
    When I try to create an auditor with HMAC salt "short" version "v1" and hash "HMAC-SHA-256"
    Then logger creation should fail with an error containing "at least"

  Scenario: Unknown algorithm rejected at startup
    When I try to create an auditor with HMAC salt "valid-salt-sixteen-b!" version "v1" and hash "MD5"
    Then logger creation should fail with an error containing "unknown"

  Scenario: Missing salt version rejected at startup
    When I try to create an auditor with HMAC salt "valid-salt-sixteen-b!" version "" and hash "HMAC-SHA-256"
    Then logger creation should fail with an error containing "version"

  # --- Salt version authentication (issue #473) ---
  #
  # These scenarios prove that `_hmac_v` (the salt version identifier)
  # is authenticated by the HMAC. Before the fix, an in-transit attacker
  # could flip the version from v1 to v2 to mislead a verifier's salt
  # lookup without detection.

  Scenario: HMAC authentication covers salt version identifier
    Given an auditor with stdout output and HMAC enabled using salt "tamper-v-salt-16-byt" version "v1" and hash "HMAC-SHA-256"
    When I audit event "user_create" with required fields
    And I close the auditor
    And I tamper with the "_hmac_v" field in the captured output setting it to "v2"
    Then independently recomputing HMAC-SHA-256 over the tampered payload with salt "tamper-v-salt-16-byt" does NOT match the "_hmac" value

  Scenario: HMAC authentication covers consumer event fields
    Given an auditor with stdout output and HMAC enabled using salt "tamper-f-salt-16-byt" version "v1" and hash "HMAC-SHA-256"
    When I audit event "user_create" with fields:
      | field    | value        |
      | outcome  | success      |
      | actor_id | alice-user01 |
    And I close the auditor
    And I tamper with the "actor_id" field in the captured output setting it to "bobby-user01"
    Then independently recomputing HMAC-SHA-256 over the tampered payload with salt "tamper-f-salt-16-byt" does NOT match the "_hmac" value

  # --- Reserved field name collision (issue #473 security-reviewer finding 6b) ---

  Scenario Outline: Reserved library field name rejected at runtime
    Given an auditor with stdout output
    When I audit event "user_create" with fields:
      | field    | value               |
      | outcome  | success             |
      | actor_id | alice               |
      | <field>  | attacker-controlled |
    Then the audit call should return an error containing "uses library-reserved field names"
    And the audit call should return an error wrapping "ErrReservedFieldName"
    And the audit call should return an error wrapping "ErrValidation"

    Examples:
      | field   |
      | _hmac   |
      | _hmac_v |

  Scenario Outline: Reserved library field name rejected even in permissive mode
    Given an auditor with stdout output and validation mode "permissive"
    When I audit event "user_create" with fields:
      | field    | value               |
      | outcome  | success             |
      | actor_id | alice               |
      | <field>  | attacker-controlled |
    Then the audit call should return an error containing "uses library-reserved field names"
    And the audit call should return an error wrapping "ErrReservedFieldName"
    And the audit call should return an error wrapping "ErrValidation"

    Examples:
      | field   |
      | _hmac   |
      | _hmac_v |

  # --- SaltVersion charset validation (issue #473 security-reviewer finding 3) ---

  Scenario Outline: SaltVersion with unsafe characters rejected at startup
    When I try to create an auditor with HMAC salt "valid-salt-sixteen-b!" version "<version>" and hash "HMAC-SHA-256"
    Then auditor creation should fail with an error containing "allowed set [A-Za-z0-9._:-]"

    Examples:
      | version    |
      | has spaces |
      | v=2        |
      | v\|1       |

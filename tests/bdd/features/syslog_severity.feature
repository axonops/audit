@syslog @docker
Feature: Syslog Severity Mapping and Cross-Cutting Features
  As a library consumer, I want audit event severity to map to syslog
  RFC 5424 severity so that SIEM systems can filter and route events
  at the syslog protocol level without parsing the JSON body. I also
  want HMAC integrity, sensitivity label stripping, CEF formatting,
  and event routing to work correctly through the syslog output.

  The mapping is:
    audit 10    → LOG_CRIT (2)     → PRI <130> with local0
    audit 8-9   → LOG_ERR (3)      → PRI <131> with local0
    audit 6-7   → LOG_WARNING (4)  → PRI <132> with local0
    audit 4-5   → LOG_NOTICE (5)   → PRI <133> with local0
    audit 1-3   → LOG_INFO (6)     → PRI <134> with local0
    audit 0     → LOG_DEBUG (7)    → PRI <135> with local0

  Background:
    Given a severity test taxonomy

  # --- PRI verification per severity band (including boundaries) ---

  Scenario Outline: Audit severity <audit_sev> produces syslog PRI <pri>
    Given a logger with syslog output on "tcp" to "localhost:5514"
    When I audit a uniquely marked "<event_type>" event
    And I close the logger
    Then the syslog server should contain the marker within 10 seconds
    And the syslog line with the marker should start with "<pri>"

    Examples:
      | event_type  | audit_sev | pri    |
      | sev10_event | 10        | <130>  |
      | sev9_event  | 9         | <131>  |
      | sev8_event  | 8         | <131>  |
      | sev7_event  | 7         | <132>  |
      | sev6_event  | 6         | <132>  |
      | sev5_event  | 5         | <133>  |
      | sev4_event  | 4         | <133>  |
      | sev3_event  | 3         | <134>  |
      | sev1_event  | 1         | <134>  |
      | sev0_event  | 0         | <135>  |

  Scenario: Different events produce different syslog PRIs
    Given a logger with syslog output on "tcp" to "localhost:5514"
    When I audit event "sev8_event" with fields and marker "pri_high":
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I audit event "sev3_event" with fields and marker "pri_low":
      | field    | value   |
      | outcome  | success |
      | actor_id | bob     |
    And I close the logger
    Then the syslog server should contain "pri_high" within 10 seconds
    And the syslog server should contain "pri_low" within 10 seconds
    And the syslog line with "pri_high" should start with "<131>"
    And the syslog line with "pri_low" should start with "<134>"

  # --- RFC 5424 message structure ---

  Scenario: Syslog message has valid RFC 5424 structure
    Given a logger with syslog output on "tcp" to "localhost:5514"
    When I audit a uniquely marked "sev5_event" event
    And I close the logger
    Then the syslog server should contain the marker within 10 seconds
    And the syslog line with the marker should start with "<133>"
    And the syslog line with the marker should contain "1 "
    And the syslog line with the marker should contain "audit"

  # --- Framework fields in JSON payload ---

  Scenario: Framework fields present in syslog JSON payload
    Given framework fields app_name "bdd-syslog" host "bdd-host" timezone "UTC"
    And a logger with syslog output on "tcp" to "localhost:5514"
    When I audit event "sev5_event" with fields and marker "fw_fields":
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I close the logger
    Then the syslog server should contain "fw_fields" within 10 seconds
    And the syslog line with "fw_fields" should contain "bdd-syslog"
    And the syslog line with "fw_fields" should contain "bdd-host"
    And the syslog line with "fw_fields" should contain "UTC"

  # --- event_category verification ---

  Scenario: event_category present in syslog output for categorised events
    Given a logger with syslog output on "tcp" to "localhost:5514"
    When I audit event "sev5_event" with fields and marker "cat_check":
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I close the logger
    Then the syslog server should contain "cat_check" within 10 seconds
    And the syslog line with "cat_check" should contain "event_category"
    And the syslog line with "cat_check" should contain "write"

  # --- CEF formatter with syslog ---

  Scenario: Syslog with CEF formatter produces CEF in MSG body
    Given a logger with syslog output on "tcp" to "localhost:5514" using CEF formatter
    When I audit event "sev8_event" with fields and marker "cef_syslog":
      | field    | value   |
      | outcome  | failure |
      | actor_id | mallory |
    And I close the logger
    Then the syslog server should contain "cef_syslog" within 10 seconds
    And the syslog line with "cef_syslog" should contain "CEF:0|"
    And the syslog line with "cef_syslog" should contain "BDDTest"
    And the syslog line with "cef_syslog" should contain "outcome=failure"
    And the syslog line with "cef_syslog" should contain "suser=mallory"

  # --- Event routing: include mode ---

  Scenario: Syslog output does not contain events excluded by include route
    Given a routing taxonomy
    And a logger with syslog output on "tcp" to "localhost:5514" routed to include only "security"
    When I audit event "user_create" with fields and marker "inc_excluded":
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I audit event "auth_failure" with fields and marker "inc_included":
      | field    | value   |
      | outcome  | failure |
      | actor_id | mallory |
    And I close the logger
    Then the syslog server should contain "inc_included" within 10 seconds
    And the syslog server should not contain "inc_excluded" within 5 seconds

  # --- Event routing: exclude mode ---

  Scenario: Syslog output excludes events matching exclude route
    Given a routing taxonomy
    And a logger with syslog output on "tcp" to "localhost:5514" routed to exclude "write"
    When I audit event "user_create" with fields and marker "exc_excluded":
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I audit event "auth_failure" with fields and marker "exc_included":
      | field    | value   |
      | outcome  | failure |
      | actor_id | mallory |
    And I close the logger
    Then the syslog server should contain "exc_included" within 10 seconds
    And the syslog server should not contain "exc_excluded" within 5 seconds

  # --- HMAC integrity with syslog ---

  Scenario: HMAC fields present in syslog output when enabled
    Given a logger with syslog output on "tcp" to "localhost:5514" and HMAC enabled with salt "syslog-hmac-salt16!" version "v1" hash "HMAC-SHA-256"
    When I audit event "sev5_event" with fields and marker "hmac_present":
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I close the logger
    Then the syslog server should contain "hmac_present" within 10 seconds
    And the syslog line with "hmac_present" should contain "_hmac"
    And the syslog line with "hmac_present" should contain "_hmac_v"
    And the syslog line with "hmac_present" should contain "v1"

  Scenario: HMAC fields absent in syslog output when not configured
    Given a logger with syslog output on "tcp" to "localhost:5514"
    When I audit event "sev5_event" with fields and marker "hmac_absent":
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I close the logger
    Then the syslog server should contain "hmac_absent" within 10 seconds
    And the syslog line with "hmac_absent" should not contain "_hmac"

  Scenario: HMAC-enabled syslog output preserves all event fields
    Given a logger with syslog output on "tcp" to "localhost:5514" and HMAC enabled with salt "syslog-hmac-full16!" version "v1" hash "HMAC-SHA-256"
    When I audit event "sev8_event" with fields and marker "hmac_full":
      | field    | value   |
      | outcome  | failure |
      | actor_id | mallory |
    And I close the logger
    Then the syslog server should contain "hmac_full" within 10 seconds
    And the syslog line with "hmac_full" should contain "sev8_event"
    And the syslog line with "hmac_full" should contain "failure"
    And the syslog line with "hmac_full" should contain "mallory"
    And the syslog line with "hmac_full" should contain "_hmac"
    And the syslog line with "hmac_full" should contain "event_category"

  # --- Sensitivity label stripping with syslog ---

  Scenario: PII field stripped from syslog output when label excluded
    Given a sensitivity test taxonomy
    And a logger with syslog output on "tcp" to "localhost:5514" excluding labels "pii"
    When I audit event "user_create" with fields and marker "strip_pii":
      | field    | value             |
      | outcome  | success           |
      | actor_id | alice             |
      | email    | alice@example.com |
    And I close the logger
    Then the syslog server should contain "strip_pii" within 10 seconds
    And the syslog line with "strip_pii" should contain "alice"
    And the syslog line with "strip_pii" should not contain "alice@example.com"

  Scenario: Non-excluded fields preserved when PII stripped from syslog
    Given a sensitivity test taxonomy
    And a logger with syslog output on "tcp" to "localhost:5514" excluding labels "pii"
    When I audit event "user_create" with fields and marker "keep_fields":
      | field    | value            |
      | outcome  | success          |
      | actor_id | bob              |
      | email    | bob@example.com  |
    And I close the logger
    Then the syslog server should contain "keep_fields" within 10 seconds
    And the syslog line with "keep_fields" should contain "user_create"
    And the syslog line with "keep_fields" should contain "bob"
    And the syslog line with "keep_fields" should contain "success"
    And the syslog line with "keep_fields" should not contain "bob@example.com"

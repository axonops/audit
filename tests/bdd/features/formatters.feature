@core @formatters
Feature: Event Formatters
  As a library consumer, I want to choose between JSON and CEF output
  formats so that events match my SIEM's expected ingestion format.

  Background:
    Given a standard test taxonomy

  # --- JSON Formatter ---

  Scenario: JSON formatter produces valid JSON with correct fields
    Given a logger with file output using JSON formatter
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I close the logger
    Then every event in the file should be valid JSON
    And the file should contain an event matching:
      | field       | value       |
      | event_type  | user_create |
      | outcome     | success     |
      | actor_id    | alice       |
      | marker      |             |
      | duration_ms |             |

  Scenario: JSON formatter produces deterministic field ordering
    Given a logger with file output using JSON formatter
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I close the logger
    Then the first JSON event should have "timestamp" before "event_type"
    And the first JSON event should have "event_type" before "outcome"

  Scenario: JSON timestamp defaults to RFC3339 with nanosecond precision
    Given a logger with file output using JSON formatter
    When I audit event "user_create" with required fields
    And I close the logger
    Then the first JSON event timestamp should match RFC3339Nano format

  Scenario: JSON timestamp can use Unix milliseconds format
    Given a logger with file output using JSON formatter with unix millis timestamps
    When I audit event "user_create" with required fields
    And I close the logger
    Then the first JSON event timestamp should be a numeric value

  Scenario: JSON OmitEmpty true omits zero-value optional fields
    Given a logger with file output using JSON formatter and OmitEmpty true
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I close the logger
    Then the first JSON event should not contain key "marker"

  Scenario: JSON OmitEmpty false includes zero-value optional fields
    Given a logger with file output using JSON formatter and OmitEmpty false
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I close the logger
    Then the first JSON event should contain key "marker"

  Scenario: JSON duration field marshalled as integer milliseconds
    Given a logger with file output using JSON formatter
    When I audit event "user_create" with a duration field
    And I close the logger
    Then the first JSON event "duration_ms" field should be an integer

  Scenario: JSON preserves Unicode values
    Given a logger with file output using JSON formatter
    When I audit event "user_create" with fields:
      | field    | value    |
      | outcome  | success  |
      | actor_id | café☕   |
    And I close the logger
    Then the file should contain an event matching:
      | field       | value       |
      | event_type  | user_create |
      | outcome     | success     |
      | actor_id    | café☕      |
      | marker      |             |
      | duration_ms |             |

  Scenario: JSON prevents newline injection in values
    Given a logger with file output using JSON formatter
    When I audit event "user_create" with a field containing a newline
    And I close the logger
    Then every event in the file should be valid JSON
    And the file should contain exactly 1 event

  # --- CEF Formatter ---

  Scenario: CEF formatter produces valid CEF header
    Given a logger with file output using CEF formatter with vendor "AxonOps" product "AuditLib" version "1.0"
    When I audit event "user_create" with required fields
    And I close the logger
    Then the file should contain a line starting with "CEF:0|"
    And the CEF line should contain "AxonOps"
    And the CEF line should contain "AuditLib"

  Scenario: CEF default severity is 5
    Given a logger with file output using CEF formatter with vendor "Test" product "Test" version "1.0"
    When I audit event "user_create" with required fields
    And I close the logger
    Then the CEF line should have severity 5

  Scenario: CEF custom severity function maps event types
    Given a logger with file output using CEF formatter with custom severity function
    When I audit event "auth_failure" with required fields
    And I close the logger
    Then the CEF line should have severity 8

  Scenario: CEF extension fields use default mapping
    Given a logger with file output using CEF formatter with vendor "Test" product "Test" version "1.0"
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I close the logger
    Then the CEF line should contain "suser=alice"
    And the CEF line should contain "outcome=success"

  Scenario: CEF header escapes pipe characters
    Given a logger with file output using CEF formatter with vendor "Axon|Ops" product "Test" version "1.0"
    When I audit event "user_create" with required fields
    And I close the logger
    Then the CEF line should contain "Axon\|Ops"

  # --- Per-output formatter ---

  Scenario: CEF null bytes are stripped from values
    Given a logger with file output using CEF formatter with vendor "Test" product "Test" version "1.0"
    When I audit event "user_create" with a field containing null bytes
    And I close the logger
    Then the file should contain a line starting with "CEF:0|"
    And every event in the file should have exactly 1 line

  Scenario: CEF severity below 0 clamped to 0
    Given a logger with file output using CEF formatter with severity below 0
    When I audit event "user_create" with required fields
    And I close the logger
    Then the CEF line should have severity 0

  Scenario: CEF extension escapes newlines as literal backslash-n
    Given a logger with file output using CEF formatter with vendor "Test" product "Test" version "1.0"
    When I audit event "user_create" with a field containing a newline
    And I close the logger
    Then the file should contain a line starting with "CEF:0|"
    And every event in the file should have exactly 1 line

  Scenario: CEF control characters stripped from extension values
    Given a logger with file output using CEF formatter with vendor "Test" product "Test" version "1.0"
    When I audit event "user_create" with a field containing control characters
    And I close the logger
    Then the file should contain a line starting with "CEF:0|"
    And every event in the file should have exactly 1 line

  Scenario: CEF invalid extension key causes serialization error without crash
    Given a logger with file output using CEF formatter with invalid field mapping
    When I audit event "user_create" with required fields
    And I close the logger
    Then no panic should have occurred
    And the file should be empty

  Scenario: Per-output formatter overrides default
    Given a logger with two file outputs using JSON and CEF formatters
    When I audit event "user_create" with required fields
    And I close the logger
    Then the JSON file should contain valid JSON
    And the CEF file should contain a line starting with "CEF:0|"

  # --- JSON encoding edge cases ---

  Scenario: JSON escapes HTML-unsafe characters
    Given a logger with file output using JSON formatter
    When I audit event "user_create" with fields:
      | field    | value       |
      | outcome  | success     |
      | actor_id | alice       |
      | marker   | <script>&   |
    And I close the logger
    Then the file should not contain raw "<script>"
    And every event in the file should be valid JSON

  Scenario: JSON HTML-safe escaping of angle brackets and ampersand
    Given a logger with file output using JSON formatter
    When I audit event "user_create" with fields:
      | field    | value          |
      | outcome  | success        |
      | actor_id | alice          |
      | marker   | <b>bold&amp;</b> |
    And I close the logger
    Then every event in the file should be valid JSON
    And the file should not contain raw "<b>"

  Scenario: JSON escapes control characters
    Given a logger with file output using JSON formatter
    When I audit event "user_create" with a field containing a tab character
    And I close the logger
    Then every event in the file should be valid JSON
    And the file should contain exactly 1 event

  # --- JSON encoding edge cases ---

  Scenario: JSON handles long string values without truncation
    Given a logger with file output using JSON formatter
    When I audit event "user_create" with a 10000-character field value
    And I close the logger
    Then every event in the file should be valid JSON
    And the file should contain exactly 1 event

  Scenario: JSON escapes U+2028 line separator
    Given a logger with file output using JSON formatter
    When I audit event "user_create" with a field containing U+2028
    And I close the logger
    Then every event in the file should be valid JSON
    And the file should contain exactly 1 event

  Scenario: JSON escapes U+2029 paragraph separator
    Given a logger with file output using JSON formatter
    When I audit event "user_create" with a field containing U+2029
    And I close the logger
    Then every event in the file should be valid JSON
    And the file should contain exactly 1 event

  Scenario: JSON replaces invalid UTF-8 with replacement character
    Given a logger with file output using JSON formatter
    When I audit event "user_create" with a field containing invalid UTF-8
    And I close the logger
    Then every event in the file should be valid JSON
    And the file should contain exactly 1 event

  # --- CEF additional scenarios ---

  Scenario: CEF severity clamped to 0-10 range
    Given a logger with file output using CEF formatter with severity above 10
    When I audit event "user_create" with required fields
    And I close the logger
    Then the CEF line should have severity 10

  Scenario: CEF header escapes backslash characters
    Given a logger with file output using CEF formatter with vendor "Axon\Ops" product "Test" version "1.0"
    When I audit event "user_create" with required fields
    And I close the logger
    Then the CEF line should contain "Axon\\Ops"

  Scenario: CEF extension escapes equals sign
    Given a logger with file output using CEF formatter with vendor "Test" product "Test" version "1.0"
    When I audit event "user_create" with fields:
      | field    | value     |
      | outcome  | a=b       |
      | actor_id | alice     |
    And I close the logger
    Then the file should contain a line starting with "CEF:0|"
    And the CEF line should contain "a\=b"

  Scenario: CEF extension escapes backslash
    Given a logger with file output using CEF formatter with vendor "Test" product "Test" version "1.0"
    When I audit event "user_create" with fields:
      | field    | value     |
      | outcome  | a\b       |
      | actor_id | alice     |
    And I close the logger
    Then the file should contain a line starting with "CEF:0|"
    And the CEF line should contain "a\\b"

  Scenario: CEF event_category uses standard ArcSight cat extension key
    Given a logger with file output using CEF formatter with vendor "Test" product "Test" version "1.0"
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I close the logger
    Then the CEF line should contain "cat=write"

  # --- CEF framework fields (#237) ---

  Scenario: CEF framework fields use correct extension keys
    Given framework fields app_name "myapp" host "prod-01" timezone "UTC"
    And a logger with file output using CEF formatter with vendor "Test" product "Test" version "1.0"
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I close the logger
    Then the CEF line should contain "deviceProcessName=myapp"
    And the CEF line should contain "dvchost=prod-01"
    And the CEF line should contain "dtz=UTC"

  Scenario: CEF pid uses dvcpid extension key
    Given a logger with file output using CEF formatter with vendor "Test" product "Test" version "1.0"
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I close the logger
    Then the CEF line should contain "dvcpid="

  Scenario: CEF app_name and host absent when not configured but timezone and pid present
    Given a logger with file output using CEF formatter with vendor "Test" product "Test" version "1.0"
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I close the logger
    Then the CEF line should not contain "deviceProcessName="
    And the CEF line should not contain "dvchost="
    And the CEF line should contain "dtz="
    And the CEF line should contain "dvcpid="

  # --- CEF reserved standard field mapping (#237) ---

  Scenario Outline: CEF maps <field> to <cef_key>
    Given a logger with file output using CEF formatter with vendor "Test" product "Test" version "1.0"
    When I audit event "user_create" with fields:
      | field    | value    |
      | outcome  | success  |
      | actor_id | alice    |
      | <field>  | <value>  |
    And I close the logger
    Then the CEF line should contain "<cef_key>=<value>"

    Examples:
      | field      | cef_key                  | value          |
      | source_ip  | src                      | 10.0.0.1       |
      | dest_ip    | dst                      | 192.168.1.1    |
      | protocol   | app                      | HTTPS          |
      | request_id | externalId               | req-123        |
      | file_name  | fname                    | report.pdf     |
      | message    | msg                      | User_created   |
      | reason     | reason                   | valid_creds    |
      | role       | spriv                    | admin          |
      | target_id  | duser                    | user-42        |

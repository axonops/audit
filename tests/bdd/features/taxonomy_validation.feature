@core @taxonomy
Feature: Taxonomy Validation
  As a library consumer, I want the auditor to validate my YAML taxonomy
  and reject malformed or inconsistent definitions so that only well-formed
  audit events can be emitted.

  The taxonomy is the contract between the library and the consumer. It
  defines event types, categories, required and optional fields, and
  default-enabled categories. Real YAML is used in these scenarios as
  living documentation of the taxonomy format.

  # --- YAML parsing ---

  Scenario: Valid full taxonomy YAML is parsed and applied
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
        security:
          - auth_failure
      events:
        user_create:
          fields:
            outcome: {required: true}
            actor_id: {required: true}
            marker: {}
        auth_failure:
          fields:
            outcome: {required: true}
            actor_id: {required: true}
      """
    Then the taxonomy should contain category "write"
    And the taxonomy should contain category "security"
    And the taxonomy should contain event type "user_create"
    And the taxonomy should contain event type "auth_failure"
    And the taxonomy event "user_create" should require field "outcome"
    And the taxonomy event "user_create" should require field "actor_id"
    Given an auditor with stdout output
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the output should contain an event matching:
      | field      | value       |
      | event_type | user_create |
      | outcome    | success     |
      | actor_id   | alice       |
      | marker     |             |

  Scenario: Minimal taxonomy with one category and one event
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        ops:
          - health_check
      events:
        health_check:
          fields:
            outcome: {required: true}
      """
    Then the taxonomy should contain category "ops"
    And the taxonomy should contain event type "health_check"
    And the taxonomy event "health_check" should require field "outcome"
    Given an auditor with stdout output
    When I audit event "health_check" with fields:
      | field   | value   |
      | outcome | success |
    Then the output should contain an event matching:
      | field      | value        |
      | event_type | health_check |
      | outcome    | success      |

  Scenario: Empty YAML input is rejected
    When I try to parse taxonomy from empty YAML
    Then the taxonomy parse should fail with exact error:
      """
      audit: invalid input: input is empty
      """

  Scenario: Oversized YAML input is rejected
    When I try to parse taxonomy from YAML exceeding 1 MiB
    Then the taxonomy parse should fail with exact error:
      """
      audit: invalid input: input size 1048577 exceeds maximum 1048576 bytes
      """

  Scenario: Invalid YAML syntax is rejected
    When I try to parse taxonomy from YAML:
      """
      version: 1
      categories:
        write: [
      """
    Then the taxonomy parse should fail wrapping "ErrInvalidInput"

  Scenario: Multi-document YAML is rejected
    When I try to parse taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
      ---
      version: 2
      """
    Then the taxonomy parse should fail with exact error:
      """
      audit: invalid input: input contains multiple YAML documents
      """

  Scenario: Unknown top-level keys are rejected
    When I try to parse taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
      unknown_key: true
      """
    Then the taxonomy parse should fail wrapping "ErrInvalidInput"

  # --- Structural validation ---

  Scenario: Missing version is rejected
    When I try to parse taxonomy from YAML:
      """
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
      """
    Then the taxonomy parse should fail wrapping "ErrTaxonomyInvalid"

  Scenario: Version 0 is rejected
    When I try to parse taxonomy from YAML:
      """
      version: 0
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
      """
    Then the taxonomy parse should fail wrapping "ErrTaxonomyInvalid"

  Scenario: Unsupported future version is rejected
    When I try to parse taxonomy from YAML:
      """
      version: 999
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
      """
    Then the taxonomy parse should fail wrapping "ErrTaxonomyInvalid"

  Scenario: Event in multiple categories is accepted
    When I try to parse taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
        admin:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
      """
    Then the taxonomy parse should succeed

  Scenario: Category member not defined in events is rejected
    When I try to parse taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
          - nonexistent_event
      events:
        user_create:
          fields:
            outcome: {required: true}
      """
    Then the taxonomy parse should fail wrapping "ErrTaxonomyInvalid"

  Scenario: Duplicate field name is rejected
    When I try to parse taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            actor_id: {required: true}
            outcome: {}
      """
    Then the taxonomy parse should fail wrapping "ErrInvalidInput"

  Scenario: Tabs in YAML are rejected
    When I try to parse taxonomy from YAML:
      """
      version: 1
      categories:
      	write:
      	  - user_create
      """
    Then the taxonomy parse should fail wrapping "ErrInvalidInput"

  Scenario: Trailing content after YAML document is rejected
    When I try to parse taxonomy YAML with trailing garbage
    Then the taxonomy parse should fail wrapping "ErrInvalidInput"

  # --- Additional structural validation ---

  Scenario: Uncategorised event is valid
    When I try to parse taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_update
      events:
        user_create:
          fields:
            outcome: {required: true}
        user_update:
          fields:
            outcome: {required: true}
      """
    Then the taxonomy parse should succeed

  # --- Validation modes ---

  Scenario: Unknown fields rejected in strict mode
    Given a standard test taxonomy
    And an auditor with stdout output and validation mode "strict"
    When I audit event "user_create" with fields:
      | field      | value   |
      | outcome    | success |
      | actor_id   | alice   |
      | extra_info | bonus   |
    Then the audit call should return an error matching:
      """
      audit: event "user_create" has unknown fields: [extra_info]
      """

  Scenario: Unknown fields accepted with warning in warn mode
    Given a standard test taxonomy
    And an auditor with stdout output and validation mode "warn"
    When I audit event "user_create" with fields:
      | field      | value   |
      | outcome    | success |
      | actor_id   | alice   |
      | extra_info | bonus   |
    Then the event should be delivered successfully

  Scenario: Unknown fields silently accepted in permissive mode
    Given a standard test taxonomy
    And an auditor with stdout output and validation mode "permissive"
    When I audit event "user_create" with fields:
      | field      | value   |
      | outcome    | success |
      | actor_id   | alice   |
      | extra_info | bonus   |
    Then the event should be delivered successfully
    And the output should contain field "extra_info" with value "bonus"

  Scenario Outline: Missing required field fails in all validation modes
    Given a standard test taxonomy
    And an auditor with stdout output and validation mode "<mode>"
    When I audit event "user_create" with fields:
      | field   | value   |
      | outcome | success |
    Then the audit call should return an error matching:
      """
      audit: event "user_create" missing required fields: [actor_id]
      """

    Examples:
      | mode       |
      | strict     |
      | warn       |
      | permissive |

  # --- Reserved standard fields (#237) ---

  Scenario: Bare reserved standard field declaration is rejected
    When I try to parse taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            source_ip: {}
      """
    Then the taxonomy parse should fail wrapping "ErrTaxonomyInvalid"
    And the taxonomy parse should fail with an error containing "reserved standard field"

  Scenario: Reserved standard field with required true is accepted
    When I try to parse taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            source_ip: {required: true}
      """
    Then the taxonomy parse should succeed

  Scenario: Reserved standard field with per-event labels is accepted
    When I try to parse taxonomy from YAML:
      """
      version: 1
      sensitivity:
        labels:
          pii:
            description: "personal info"
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            source_ip:
              labels: [pii]
      """
    Then the taxonomy parse should succeed

  Scenario: Reserved standard field with global label is accepted
    When I try to parse taxonomy from YAML:
      """
      version: 1
      sensitivity:
        labels:
          pii:
            fields: [source_ip]
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            source_ip: {}
      """
    Then the taxonomy parse should succeed

  Scenario: Reserved standard field without declaration accepted in strict mode
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
      """
    And an auditor with stdout output and validation mode "strict"
    When I audit event "user_create" with fields:
      | field     | value    |
      | outcome   | success  |
      | source_ip | 10.0.0.1 |
    Then the event should be delivered successfully
    And the output should contain field "source_ip" with value "10.0.0.1"

  Scenario: Reserved standard field with sensitivity label can be stripped
    Given a taxonomy from YAML:
      """
      version: 1
      sensitivity:
        labels:
          pii:
            description: "personal info"
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            source_ip:
              labels: [pii]
      """
    And an auditor with stdout output excluding labels "pii"
    When I audit event "user_create" with fields:
      | field     | value    |
      | outcome   | success  |
      | source_ip | 10.0.0.1 |
    Then the output should not contain field "source_ip"

  # --- Framework fields cannot be declared as user fields (#237) ---

  Scenario Outline: Framework field <field> declared in taxonomy is rejected
    When I try to parse taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            <field>: {}
      """
    Then the taxonomy parse should fail wrapping "ErrTaxonomyInvalid"
    And the taxonomy parse should fail with an error containing "reserved framework field"

    Examples:
      | field          |
      | timestamp      |
      | event_type     |
      | severity       |
      | event_category |
      | app_name       |
      | host           |
      | timezone       |
      | pid            |

  # --- Framework fields cannot be labeled (#237) ---

  Scenario Outline: Labeling framework field <field> via global mapping is rejected
    When I try to parse taxonomy from YAML:
      """
      version: 1
      sensitivity:
        labels:
          internal:
            fields: [<field>]
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
      """
    Then the taxonomy parse should fail wrapping "ErrTaxonomyInvalid"
    And the taxonomy parse should fail with an error containing "protected framework field"

    Examples:
      | field          |
      | app_name       |
      | host           |
      | timezone       |
      | pid            |

  Scenario: Undeclared reserved standard field accepted in permissive mode
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
      """
    And an auditor with stdout output and validation mode "permissive"
    When I audit event "user_create" with fields:
      | field     | value    |
      | outcome   | success  |
      | source_ip | 10.0.0.1 |
    Then the event should be delivered successfully
    And the output should contain field "source_ip" with value "10.0.0.1"

  Scenario: Undeclared reserved standard field accepted in warn mode
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
      """
    And an auditor with stdout output and validation mode "warn"
    When I audit event "user_create" with fields:
      | field     | value    |
      | outcome   | success  |
      | source_ip | 10.0.0.1 |
    Then the event should be delivered successfully
    And the output should contain field "source_ip" with value "10.0.0.1"

  # --- Name character-set and length validation (#477) ---
  #
  # Every consumer-controlled taxonomy identifier — category name,
  # event type key, required/optional field name, and sensitivity
  # label name — must match `^[a-z][a-z0-9_]*$` and be no longer than
  # 128 bytes. The rule keeps bidi-override characters, Unicode
  # confusables, CEF/JSON metacharacters, C0/C1 control bytes, and
  # extremely long names out of downstream log consumers and SIEM
  # dashboards. Violations wrap BOTH `ErrTaxonomyInvalid` and
  # `ErrInvalidTaxonomyName` so consumers can discriminate.

  Scenario: Event type name with uppercase is rejected
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - UserCreate
      events:
        UserCreate:
          fields:
            outcome: {required: true}
      """
    Then the taxonomy parse should fail wrapping "ErrTaxonomyInvalid"
    And the taxonomy parse should fail wrapping "ErrInvalidTaxonomyName"
    And the taxonomy parse should fail with an error containing "UserCreate"

  Scenario: Event type name with hyphen is rejected
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user-create
      events:
        user-create:
          fields:
            outcome: {required: true}
      """
    Then the taxonomy parse should fail wrapping "ErrInvalidTaxonomyName"

  Scenario: Event type name with bidi override is rejected
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - "user\u202eadmin"
      events:
        "user\u202eadmin":
          fields:
            outcome: {required: true}
      """
    Then the taxonomy parse should fail wrapping "ErrInvalidTaxonomyName"

  Scenario: Field name with dot is rejected
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            "actor.id": {required: true}
      """
    Then the taxonomy parse should fail wrapping "ErrInvalidTaxonomyName"
    And the taxonomy parse should fail with an error containing "actor.id"

  Scenario: Category name with uppercase is rejected
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        Write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
      """
    Then the taxonomy parse should fail wrapping "ErrInvalidTaxonomyName"
    And the taxonomy parse should fail with an error containing "Write"

  Scenario: Sensitivity label name with hyphen is rejected
    Given a taxonomy from YAML:
      """
      version: 1
      sensitivity:
        labels:
          "PII-data":
            fields: [email]
      categories:
        write:
          - user_create
      events:
        user_create:
          fields:
            outcome: {required: true}
            email: {}
      """
    Then the taxonomy parse should fail wrapping "ErrInvalidTaxonomyName"
    And the taxonomy parse should fail with an error containing "PII-data"

  Scenario: Overlong event type name is rejected as a DoS defence
    Given a taxonomy from YAML with a 200-byte event type name
    Then the taxonomy parse should fail wrapping "ErrInvalidTaxonomyName"
    And the taxonomy parse should fail with an error containing "exceeds maximum length 128 bytes"

  Scenario: Error message quotes bidi bytes as Go escape sequences
    Given a taxonomy from YAML:
      """
      version: 1
      categories:
        write:
          - "user\u202eadmin"
      events:
        "user\u202eadmin":
          fields:
            outcome: {required: true}
      """
    Then the taxonomy parse should fail wrapping "ErrInvalidTaxonomyName"
    And the taxonomy parse error should not contain raw bidi bytes
    And the taxonomy parse error should contain escaped "\u202e"

  Scenario: Valid name at exactly 128 bytes is accepted
    Given a taxonomy from YAML with a 128-byte event type name
    Then the taxonomy parse should succeed

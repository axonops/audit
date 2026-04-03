@core @config
Feature: YAML Output Configuration
  As a library consumer, I want to configure audit outputs via a YAML
  file so that I can wire outputs without writing Go code.

  Scenario: Load minimal stdout-only config from YAML
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        console:
          type: stdout
      """
    When I create a logger from the YAML config
    And I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I close the logger
    Then the audit call should have succeeded

  Scenario: Load file output with routing from YAML
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        all_events:
          type: file
          file:
            path: "${AUDIT_BDD_DIR}/all.log"
        write_only:
          type: file
          file:
            path: "${AUDIT_BDD_DIR}/writes.log"
          route:
            include_categories:
              - write
      """
    When I create a logger from the YAML config
    And I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I audit event "auth_failure" with fields:
      | field   | value   |
      | outcome | failure |
    And I close the logger
    Then the file "all.log" should contain "user_create"
    And the file "all.log" should contain "auth_failure"
    And the file "writes.log" should contain "user_create"
    And the file "writes.log" should not contain "auth_failure"

  Scenario: Unknown output type returns helpful error
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        broken:
          type: kafka
      """
    When I try to create a logger from the YAML config
    Then the config load should fail with an error containing "unknown output type"
    And the config load error should contain "did you import"

  Scenario: Missing environment variable returns clear error
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        bad:
          type: file
          file:
            path: "${TOTALLY_UNDEFINED_BDD_VAR}/audit.log"
      """
    When I try to create a logger from the YAML config
    Then the config load should fail with an error containing "TOTALLY_UNDEFINED_BDD_VAR"

  # --- Framework fields in output config (#237) ---

  Scenario: Missing app_name in output config YAML is rejected
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      host: test
      outputs:
        console:
          type: stdout
      """
    When I try to create a logger from the YAML config
    Then the config load should fail with an error containing "app_name is required"

  Scenario: Missing host in output config YAML is rejected
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      outputs:
        console:
          type: stdout
      """
    When I try to create a logger from the YAML config
    Then the config load should fail with an error containing "host is required"

  Scenario: timezone optional in output config YAML
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        console:
          type: stdout
      """
    When I create a logger from the YAML config
    And I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the audit call should have succeeded

  Scenario: timezone present in output config YAML
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      timezone: UTC
      outputs:
        console:
          type: stdout
      """
    When I create a logger from the YAML config
    And I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the audit call should have succeeded

  # --- standard_fields in output config (#237) ---

  Scenario: standard_fields with valid reserved field accepted
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      standard_fields:
        source_ip: "10.0.0.1"
      outputs:
        console:
          type: stdout
      """
    When I create a logger from the YAML config
    And I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the audit call should have succeeded

  Scenario: standard_fields with unknown field rejected
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      standard_fields:
        bogus_field: "value"
      outputs:
        console:
          type: stdout
      """
    When I try to create a logger from the YAML config
    Then the config load should fail with an error containing "unknown field"

  Scenario: standard_fields with empty value rejected
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      standard_fields:
        source_ip: ""
      outputs:
        console:
          type: stdout
      """
    When I try to create a logger from the YAML config
    Then the config load should fail with an error containing "non-empty"

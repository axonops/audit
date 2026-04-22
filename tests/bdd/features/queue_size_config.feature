@core @config
Feature: Queue Size YAML Configuration
  As a library consumer, I want to configure the core intake queue
  via queue_size in the YAML auditor section so that I can control
  back-pressure behaviour.

  The auditor-level queue was renamed from buffer_size to queue_size
  to avoid confusion with per-output buffer_size. The old field name
  is rejected as an unknown field.

  Background:
    Given a standard test taxonomy

  Scenario: queue_size accepted in auditor section
    Given the following outputs YAML:
      """
      version: 1
      app_name: bdd-test
      host: bdd-host
      auditor:
        queue_size: 500
      outputs:
        console:
          type: stdout
      """
    When I load the outputs config
    Then the config should load successfully
    And the auditor queue_size should be 500

  Scenario: queue_size exceeding maximum is rejected via YAML
    Given the following outputs YAML:
      """
      version: 1
      app_name: bdd-test
      host: bdd-host
      auditor:
        queue_size: 2000000
      outputs:
        console:
          type: stdout
      """
    When I load the outputs config
    Then the config load should fail with an error containing "exceeds maximum"

  Scenario: queue_size defaults to zero when omitted
    Given the following outputs YAML:
      """
      version: 1
      app_name: bdd-test
      host: bdd-host
      outputs:
        console:
          type: stdout
      """
    When I load the outputs config
    Then the config should load successfully
    And the auditor queue_size should be 10000

  Scenario: Old buffer_size under auditor section is rejected
    Given the following outputs YAML:
      """
      version: 1
      app_name: bdd-test
      host: bdd-host
      auditor:
        buffer_size: 1000
      outputs:
        console:
          type: stdout
      """
    When I load the outputs config
    Then the config load should fail with an error containing "unknown field"

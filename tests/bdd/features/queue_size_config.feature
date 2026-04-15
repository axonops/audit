@core @config
Feature: Queue Size YAML Configuration
  As a library consumer, I want to configure the core intake queue
  via queue_size in the YAML logger section so that I can control
  back-pressure behaviour.

  The logger-level queue was renamed from buffer_size to queue_size
  to avoid confusion with per-output buffer_size. The old field name
  is rejected as an unknown field.

  Background:
    Given a standard test taxonomy

  Scenario: queue_size accepted in logger section
    Given the following outputs YAML:
      """
      version: 1
      app_name: bdd-test
      host: bdd-host
      logger:
        queue_size: 500
      outputs:
        console:
          type: stdout
      """
    When I load the outputs config
    Then the config should load successfully
    And the loaded config queue_size should be 500

  Scenario: Old buffer_size under logger section is rejected
    Given the following outputs YAML:
      """
      version: 1
      app_name: bdd-test
      host: bdd-host
      logger:
        buffer_size: 1000
      outputs:
        console:
          type: stdout
      """
    When I load the outputs config
    Then the config load should fail with an error containing "unknown field"

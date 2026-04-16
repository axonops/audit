@core @metrics
Feature: OutputMetrics Factory
  As a library consumer, I want to pass an OutputMetricsFactory to
  outputconfig.Load so that each output receives a scoped OutputMetrics
  instance for per-output buffer telemetry (drops, flushes, errors,
  retries, queue depth).

  The factory func(outputType, outputName string) audit.OutputMetrics is
  called once per output. The namedOutput wrapper (from WrapOutput)
  implements OutputMetricsReceiver for all outputs, forwarding to the
  inner output when it implements the interface. A nil factory is safe
  — outputs work without per-output metrics.

  Background:
    Given a standard test taxonomy
    And a mock output metrics factory is configured

  Scenario: Factory receives correct output type and output name for a file output
    Given the following outputs YAML:
      """
      version: 1
      app_name: bdd-test
      host: bdd-host
      outputs:
        compliance_archive:
          type: file
          file:
            path: /tmp/bdd-factory-file.log
      """
    When I load the outputs config with the output metrics factory
    Then the config should load successfully
    And the output metrics factory should have been called 1 time
    And the output metrics factory should have been called with type "file" and name "compliance_archive"

  Scenario: Factory called once per output with distinct instances
    Given the following outputs YAML:
      """
      version: 1
      app_name: bdd-test
      host: bdd-host
      outputs:
        audit_log:
          type: file
          file:
            path: /tmp/bdd-factory-multi-a.log
        backup_log:
          type: file
          file:
            path: /tmp/bdd-factory-multi-b.log
        console:
          type: stdout
      """
    When I load the outputs config with the output metrics factory
    Then the config should load successfully
    And the output metrics factory should have been called 3 times
    And the output metrics factory should have been called with type "file" and name "audit_log"
    And the output metrics factory should have been called with type "file" and name "backup_log"
    And the output metrics factory should have been called with type "stdout" and name "console"
    And the metrics instance for "file:audit_log" should not be the same as "file:backup_log"

  Scenario: Factory called for stdout output via namedOutput wrapper
    Given the following outputs YAML:
      """
      version: 1
      app_name: bdd-test
      host: bdd-host
      outputs:
        console:
          type: stdout
      """
    When I load the outputs config with the output metrics factory
    Then the config should load successfully
    And the output metrics factory should have been called 1 time
    And the output metrics factory should have been called with type "stdout" and name "console"

  Scenario: Nil factory does not panic
    Given the following outputs YAML:
      """
      version: 1
      app_name: bdd-test
      host: bdd-host
      outputs:
        audit_log:
          type: file
          file:
            path: /tmp/bdd-factory-nil.log
      """
    When I load the outputs config without an output metrics factory
    Then the config should load successfully

  Scenario: Factory not called for unknown output type
    Given the following outputs YAML:
      """
      version: 1
      app_name: bdd-test
      host: bdd-host
      outputs:
        broken:
          type: kafka
      """
    When I load the outputs config with the output metrics factory
    Then the config load should fail with an error containing "unknown output type"
    And the output metrics factory should have been called 0 times

  Scenario: Factory not called for disabled output
    Given the following outputs YAML:
      """
      version: 1
      app_name: bdd-test
      host: bdd-host
      outputs:
        disabled_log:
          type: file
          enabled: false
          file:
            path: /tmp/bdd-factory-disabled.log
        active_log:
          type: file
          file:
            path: /tmp/bdd-factory-active.log
      """
    When I load the outputs config with the output metrics factory
    Then the config should load successfully
    And the output metrics factory should have been called 1 time
    And the output metrics factory should have been called with type "file" and name "active_log"

  Scenario: Created OutputMetrics wired to output via SetOutputMetrics
    Given the following outputs YAML:
      """
      version: 1
      app_name: bdd-test
      host: bdd-host
      outputs:
        audit_log:
          type: file
          file:
            path: /tmp/bdd-factory-wired.log
            buffer_size: 100
      """
    When I load the outputs config with the output metrics factory
    Then the config should load successfully
    And the output metrics factory should have been called with type "file" and name "audit_log"
    When I create a logger from the loaded config
    And I audit event "user_create" with required fields
    And I close the logger
    Then the output metrics for "file:audit_log" should have recorded at least 1 flush
    And the output metrics for "file:audit_log" should have recorded 0 errors
    And the output metrics for "file:audit_log" should have recorded 0 drops

  Scenario: Factory returning nil does not panic
    Given the following outputs YAML:
      """
      version: 1
      app_name: bdd-test
      host: bdd-host
      outputs:
        audit_log:
          type: file
          file:
            path: /tmp/bdd-factory-nil-return.log
      """
    When I load the outputs config with a nil-returning output metrics factory
    Then the config should load successfully
    When I create a logger from the loaded config
    And I audit event "user_create" with required fields
    And I close the logger
    Then the event should be delivered successfully

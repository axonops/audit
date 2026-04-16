@core @config
Feature: Per-Output Buffer Configuration
  As a library consumer, I want to configure the internal async buffer
  size for each file and syslog output via buffer_size in YAML so that
  I can tune back-pressure per output independently.

  Each async output (file, syslog) has an internal buffered channel.
  The buffer_size field controls its capacity. Values exceeding the
  maximum (100,000) are rejected. When omitted, the default (10,000)
  is used.

  Background:
    Given a standard test taxonomy

  Scenario: File output buffer_size accepted in YAML
    Given the following outputs YAML:
      """
      version: 1
      app_name: bdd-test
      host: bdd-host
      outputs:
        audit_log:
          type: file
          file:
            path: /tmp/bdd-buffer-test.log
            buffer_size: 500
      """
    When I load the outputs config
    Then the config should load successfully

  Scenario: File output buffer_size exceeding maximum is rejected
    Given the following outputs YAML:
      """
      version: 1
      app_name: bdd-test
      host: bdd-host
      outputs:
        audit_log:
          type: file
          file:
            path: /tmp/bdd-buffer-test.log
            buffer_size: 200000
      """
    When I load the outputs config
    Then the config load should fail with an error containing "buffer_size"

  Scenario: File output defaults buffer_size when omitted
    Given a logger with file output at a temporary path
    When I audit 50 events rapidly
    And I close the logger
    Then the file should contain exactly 50 events

  Scenario: Syslog output buffer_size exceeding maximum is rejected
    Given the following outputs YAML:
      """
      version: 1
      app_name: bdd-test
      host: bdd-host
      outputs:
        audit_syslog:
          type: syslog
          syslog:
            address: "localhost:99999"
            buffer_size: 200000
      """
    When I load the outputs config
    Then the config load should fail with an error containing "buffer_size 200000 exceeds maximum 100000"

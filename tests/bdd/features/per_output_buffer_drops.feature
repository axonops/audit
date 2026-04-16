@core @isolation
Feature: Per-Output Buffer Drops
  As a library consumer, I want each output's internal buffer drops to
  be tracked independently via OutputMetrics.RecordDrop so that I can
  identify which output is overwhelmed without affecting other outputs.

  All outputs except stdout have internal async buffers. When an output's
  buffer is full, Write() drops the event silently (returns nil) and
  calls OutputMetrics.RecordDrop(). The core drain goroutine never sees
  an error — per-output drops are invisible to the core pipeline.

  Background:
    Given a standard test taxonomy

  Scenario: File output drops events when internal buffer is full
    Given a file output with buffer_size 1 and mock output metrics
    And a logger with that file output and queue_size 10000
    When I audit 100 events rapidly
    And I close the logger
    Then the output metrics should have recorded at least 1 drop

  Scenario: Per-output drop does not cause core output error
    Given a file output with buffer_size 1 and mock output metrics
    And mock metrics are configured
    And a logger with that file output and pipeline metrics and queue_size 10000
    When I audit 100 events rapidly
    And I close the logger
    Then the output metrics should have recorded at least 1 drop
    And the pipeline metrics should not have recorded an output error for file

  Scenario: Core queue drops and per-output drops are independent
    Given a file output with buffer_size 1 and mock output metrics
    And mock metrics are configured
    And a logger with that file output and pipeline metrics and queue_size 5
    When I fill the logger buffer beyond capacity
    And I close the logger
    Then the metrics should have recorded at least 1 buffer drop
    And the output metrics should have recorded at least 1 drop

  Scenario: Multiple outputs with different buffer sizes drop independently
    Given a file output with buffer_size 1 and mock output metrics
    And a logger with that file output and a stdout output
    When I audit 50 events rapidly
    And I close the logger
    Then the output metrics should have recorded at least 1 drop

  @docker @syslog
  Scenario: Syslog output drops events when internal buffer is full
    Given a syslog output with buffer_size 1 and mock output metrics
    And a logger with those outputs and queue_size 10000
    When I audit 100 events rapidly
    And I close the logger
    Then the output metrics should have recorded at least 1 drop

  @docker @webhook
  Scenario: Webhook output drops events when internal buffer is full
    Given a webhook output with buffer_size 1 and mock output metrics
    And a logger with those outputs and queue_size 10000
    When I audit 200 events rapidly
    And I close the logger
    Then the output metrics should have recorded at least 1 drop

  @docker @loki
  Scenario: Loki output drops events when internal buffer is full
    Given a loki output with buffer_size 100 and mock output metrics
    And a logger with those outputs and queue_size 10000
    When I audit 500 events rapidly
    And I close the logger
    Then the output metrics should have recorded at least 1 drop

@core @isolation
Feature: Output Isolation
  As a library consumer, I want a slow or dead output to NOT block
  delivery to other outputs so that a DDoS on one output endpoint
  does not cascade to silence all auditing.

  All outputs except stdout have internal async buffers. Write()
  copies data into a buffered channel and returns immediately. A
  background goroutine handles the actual I/O. This ensures one
  output's I/O latency does not block the drain goroutine from
  delivering to other outputs.

  Background:
    Given a standard test taxonomy

  Scenario: Events delivered to all outputs after close
    Given a logger with stdout and a recording mock output
    When I audit 5 events rapidly
    And I close the logger
    Then stdout should have received all 5 events
    And the recording output should have received all 5 events

  Scenario: Stdout remains synchronous
    Given a logger with stdout output only
    When I audit event "user_create" with required fields
    And I close the logger
    Then stdout should have received the event before close returned

  Scenario: Multiple recording outputs each receive all events
    Given a logger with two recording mock outputs
    When I audit 5 events rapidly
    And I close the logger
    Then both recording outputs should have received all 5 events
